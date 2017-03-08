//
// Copyright © 2016 Associated Universities, Inc. Washington DC, USA.
//
// This file is part of vysmaw.
//
// vysmaw is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// vysmaw is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// vysmaw.  If not, see <http://www.gnu.org/licenses/>.
//
#include <vysmaw_private.h>
#include <glib.h>
#include <string.h>

struct vysmaw_message *
vysmaw_message_queue_pop(vysmaw_message_queue queue)
{
	g_async_queue_lock(queue->q);
	struct vysmaw_message *result = g_async_queue_pop_unlocked(queue->q);
	queue->depth--;
	g_async_queue_unlock(queue->q);
	message_queue_unref(queue); // release message's queue reference
	return result;
}

struct vysmaw_message *
vysmaw_message_queue_timeout_pop(vysmaw_message_queue queue, uint64_t timeout)
{
	struct vysmaw_message *result;
	g_async_queue_lock(queue->q);
#if GLIB_CHECK_VERSION(2,32,0)
	result = g_async_queue_timeout_pop_unlocked(queue->q, timeout);
#else
	GTimeVal end;
	g_get_current_time(&end);
	g_time_val_add(&end, timeout);
	result = g_async_queue_timed_pop_unlocked(queue->q, &end);
#endif
	if (result != NULL)
		queue->depth--;
	g_assert(queue->depth >= 0);
	g_async_queue_unlock(queue->q);
	/* release message's queue reference */
	if (result != NULL) message_queue_unref(queue);
	return result;
}

struct vysmaw_message *
vysmaw_message_queue_try_pop(vysmaw_message_queue queue)
{
	g_async_queue_lock(queue->q);
	struct vysmaw_message *result = g_async_queue_try_pop_unlocked(queue->q);
	if (result != NULL)
		queue->depth--;
	g_assert(queue->depth >= 0);
	g_async_queue_unlock(queue->q);
	/* release message's queue reference */
	if (result != NULL) message_queue_unref(queue);
	return result;
}

void
vysmaw_message_unref(struct vysmaw_message *message)
{
	if (g_atomic_int_dec_and_test(&message->refcount)) {
		vysmaw_message_free_resources(message);
		g_slice_free(struct vysmaw_message, message);
	}
}

vysmaw_handle
vysmaw_start_(const struct vysmaw_configuration *config,
              unsigned num_consumers, struct vysmaw_consumer *consumers)
{
	GPtrArray *cps = g_ptr_array_new();
	for (unsigned i = num_consumers; i > 0; --i) {
		g_ptr_array_add(cps, consumers);
		++consumers;
	}
	vysmaw_handle result = vysmaw_start(
		config, num_consumers, (struct vysmaw_consumer **)cps->pdata);
	g_ptr_array_free(cps, TRUE);
	return result;
}

vysmaw_handle
vysmaw_start(const struct vysmaw_configuration *config,
             unsigned num_consumers, struct vysmaw_consumer **consumers)
{
	THREAD_INIT;

	/* "global" handle initialization */
	vysmaw_handle result = g_new0(struct _vysmaw_handle, 1);
	/* result is initialized with a reference count of 2: one for the caller,
	 * and another for the end message that we guarantee will be posted for
	 * every consumer */
	result->refcount = 2;
	MUTEX_INIT(result->mtx);
	result->in_shutdown = false;
	result->result = NULL;
	memcpy((void *)&result->config, config, sizeof(*config));
	if (result->config.error_record == NULL) {
		*(unsigned *)&result->config.max_spectrum_buffer_size =
			MAX(result->config.max_spectrum_buffer_size,
			    VYS_BUFFER_POOL_MIN_BUFFER_SIZE);
		if (result->config.single_spectrum_buffer_pool) {
			size_t num_buffers =
				result->config.spectrum_buffer_pool_size
				/ result->config.max_spectrum_buffer_size;
			result->pool = spectrum_buffer_pool_new(
				result->config.max_spectrum_buffer_size, num_buffers);
			result->new_valid_buffer_fn = new_valid_buffer_from_pool;
			result->lookup_buffer_pool_fn = lookup_buffer_pool_from_pool;
			result->list_buffer_pools_fn = buffer_pool_list_from_pool;
		} else {
			MUTEX_INIT(result->pool_collection_mtx);
			result->pool_collection = spectrum_buffer_pool_collection_new();
			result->new_valid_buffer_fn = new_valid_buffer_from_collection;
			result->lookup_buffer_pool_fn = lookup_buffer_pool_from_collection;
			result->list_buffer_pools_fn = buffer_pool_list_from_collection;
		}
	}

	/* per consumer initialization */
	GArray *priv_consumers =
		g_array_new(FALSE, FALSE, sizeof(struct consumer));
	for (unsigned i = num_consumers; i > 0; --i) {
		init_consumer((*consumers)->filter, (*consumers)->filter_data,
		              &(*consumers)->queue, priv_consumers);
		++consumers;
	}
	result->num_consumers = num_consumers;
	result->consumers = (struct consumer *)g_array_free(priv_consumers, false);

	if (result->config.error_record == NULL) {
		/* service threads initialization */
		MUTEX_INIT(result->gate.mtx);
		COND_INIT(result->gate.cond);
		init_service_threads(result);
	}
	if (result->config.error_record != NULL) {
		result->in_shutdown = true;
		struct vysmaw_result rc = {
			.code = VYSMAW_SYSERR,
			.syserr_desc = vys_error_record_to_string(
				(struct vys_error_record **)&(result->config.error_record))
		};
		struct vysmaw_message *msg = end_message_new(result, &rc);
		post_msg(result, msg);
		handle_unref(result); // end message has been posted
	}
	return result;
}

void
vysmaw_shutdown(vysmaw_handle handle)
{
	begin_shutdown(handle, NULL);
	handle_unref(handle); // release caller's ref
}

struct vysmaw_configuration *
vysmaw_configuration_new(const char *path)
{
	struct vysmaw_configuration *result =
		g_try_new0(struct vysmaw_configuration, 1);
	if (G_UNLIKELY(result == NULL)) return NULL;

	char *vys_base = config_vys_base();
	char *vysmaw_base = config_vysmaw_base();
	char *pcfg = load_config(path, &(result->error_record));
	if (result->error_record == NULL) {
		char *cfg = g_strjoin("\n", vys_base, vysmaw_base, pcfg, NULL);
		GKeyFile *kf = g_key_file_new();
		if (g_key_file_load_from_data(kf, cfg, -1, G_KEY_FILE_NONE, NULL)) {
			init_from_key_file_vysmaw(kf, result);
		} else {
			MSG_ERROR(&(result->error_record), -1, "%s",
			          "Failed to merge configuration files");
		}
		g_key_file_free(kf);
		g_free(cfg);
	}
	g_free(pcfg);
	g_free(vysmaw_base);
	g_free(vys_base);
	return result;
}

void
vysmaw_configuration_free(struct vysmaw_configuration *config)
{
	vys_error_record_free(config->error_record);
	g_free(config);
}

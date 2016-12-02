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

#define DEFAULT_SIGNAL_MULTICAST_ADDRESS "224.0.0.100"
#define DEFAULT_SPECTRUM_BUFFER_POOL_SIZE (10 * (1 << 20))
#define DEFAULT_SINGLE_SPECTRUM_BUFFER_POOL (10 * (1 << 20))
#define DEFAULT_MAX_SPECTRUM_BUFFER_SIZE (1 << 10)
#define DEFAULT_SIGNAL_MESSAGE_POOL_SIZE (10 * (1 << 20))
#define DEFAULT_EAGER_CONNECT true
#define DEFAULT_EAGER_CONNECT_IDLE_SEC 1
#define DEFAULT_PRECONNECT_BACKLOG true
#define DEFAULT_MAX_DEPTH_MESSAGE_QUEUE 1000
#define DEFAULT_QUEUE_RESUME_OVERHEAD 100
#define DEFAULT_MAX_STARVATION_LATENCY 100
#define DEFAULT_RESOLVE_ROUTE_TIMEOUT_MS 1000
#define DEFAULT_RESOLVE_ADDR_TIMEOUT_MS 1000
#define DEFAULT_INACTIVE_SERVER_TIMEOUT_SEC (60 * 60 * 12)
#define DEFAULT_SHUTDOWN_CHECK_INTERVAL_MS 1000
#define DEFAULT_SIGNAL_RECEIVE_MAX_POSTED 10000
#define DEFAULT_SIGNAL_RECEIVE_MIN_ACK_PART 10
#define DEFAULT_RDMA_READ_MAX_POSTED 1000
#define DEFAULT_RDMA_READ_MIN_ACK_PART 10

struct vysmaw_message *
vysmaw_message_queue_pop(vysmaw_message_queue queue)
{
	return message_queue_pop(queue);
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
	if (result != NULL) queue->depth--;
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
	if (result != NULL) queue->depth--;
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
	result->refcount = 1;
	MUTEX_INIT(result->mtx);
	result->in_shutdown = false;
	result->result = NULL;
	memcpy((void *)&result->config, config, sizeof(*config));
	if (config->single_spectrum_buffer_pool) {
		size_t num_buffers =
			config->spectrum_buffer_pool_size
			/ config->max_spectrum_buffer_size;
		result->pool = spectrum_buffer_pool_new(
			config->max_spectrum_buffer_size, num_buffers);
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

	/* service threads initialization */
	MUTEX_INIT(result->gate.mtx);
	COND_INIT(result->gate.cond);
	int rc = init_service_threads(result);
	if (rc != 0) {
		handle_unref(result);
		result = NULL;
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
		g_try_new(struct vysmaw_configuration, 1);
	if (G_UNLIKELY(result == NULL)) return NULL;

	g_strlcpy(result->signal_multicast_address,
	          DEFAULT_SIGNAL_MULTICAST_ADDRESS,
	          sizeof(result->signal_multicast_address));
	result->spectrum_buffer_pool_size = DEFAULT_SPECTRUM_BUFFER_POOL_SIZE;
	result->single_spectrum_buffer_pool = DEFAULT_SINGLE_SPECTRUM_BUFFER_POOL;
	result->max_spectrum_buffer_size = DEFAULT_MAX_SPECTRUM_BUFFER_SIZE;
	result->signal_message_pool_size = DEFAULT_SIGNAL_MESSAGE_POOL_SIZE;
	result->eager_connect = DEFAULT_EAGER_CONNECT;
	result->eager_connect_idle_sec = DEFAULT_EAGER_CONNECT_IDLE_SEC;
	result->preconnect_backlog = DEFAULT_PRECONNECT_BACKLOG;
	result->max_depth_message_queue = DEFAULT_MAX_DEPTH_MESSAGE_QUEUE;
	result->queue_resume_overhead = DEFAULT_QUEUE_RESUME_OVERHEAD;
	result->max_starvation_latency = DEFAULT_MAX_STARVATION_LATENCY;
	result->resolve_route_timeout_ms = DEFAULT_RESOLVE_ROUTE_TIMEOUT_MS;
	result->resolve_addr_timeout_ms = DEFAULT_RESOLVE_ADDR_TIMEOUT_MS;
	result->inactive_server_timeout_sec = DEFAULT_INACTIVE_SERVER_TIMEOUT_SEC;
	result->shutdown_check_interval_ms = DEFAULT_SHUTDOWN_CHECK_INTERVAL_MS;
	result->signal_receive_max_posted = DEFAULT_SIGNAL_RECEIVE_MAX_POSTED;
	result->signal_receive_min_ack_part = DEFAULT_SIGNAL_RECEIVE_MIN_ACK_PART;
	result->rdma_read_max_posted = DEFAULT_RDMA_READ_MAX_POSTED;
	result->rdma_read_min_ack_part = DEFAULT_RDMA_READ_MIN_ACK_PART;
	return result;
}

void
vysmaw_configuration_free(struct vysmaw_configuration *config)
{
	vys_error_record_free(config->error_record);
	g_free(config);
}

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
#include <signal_receiver.h>
#include <spectrum_selector.h>
#include <spectrum_reader.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>

#define DEFAULT_SPECTRUM_BUFFER_POOL_SIZE (10 * (1 << 20))
#define DEFAULT_SINGLE_SPECTRUM_BUFFER_POOL true
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

static gchar *default_config_vysmaw()
	__attribute__((returns_nonnull,malloc));
static guint64 parse_uint64(
	GKeyFile *kf, const gchar *key,
	struct vysmaw_configuration *config)
	__attribute__((nonnull));
static gboolean parse_boolean(
	GKeyFile *kf, const gchar *key,
	struct vysmaw_configuration *config)
	__attribute__((nonnull));
static gdouble parse_double(
	GKeyFile *kf, const gchar *key,
	struct vysmaw_configuration *config)
	__attribute__((nonnull));

static gchar *
default_config_vysmaw()
{
	GKeyFile *kf = g_key_file_new();
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      SPECTRUM_BUFFER_POOL_SIZE_KEY,
	                      DEFAULT_SPECTRUM_BUFFER_POOL_SIZE);
	g_key_file_set_boolean(kf, VYSMAW_CONFIG_GROUP_NAME,
	                       SINGLE_SPECTRUM_BUFFER_POOL_KEY,
	                       DEFAULT_SINGLE_SPECTRUM_BUFFER_POOL);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      MAX_SPECTRUM_BUFFER_SIZE_KEY,
	                      DEFAULT_MAX_SPECTRUM_BUFFER_SIZE);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      SIGNAL_MESSAGE_POOL_SIZE_KEY,
	                      DEFAULT_SIGNAL_MESSAGE_POOL_SIZE);
	g_key_file_set_boolean(kf, VYSMAW_CONFIG_GROUP_NAME,
	                       EAGER_CONNECT_KEY,
	                       DEFAULT_EAGER_CONNECT);
	g_key_file_set_double(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      EAGER_CONNECT_IDLE_SEC_KEY,
	                      DEFAULT_EAGER_CONNECT_IDLE_SEC);
	g_key_file_set_boolean(kf, VYSMAW_CONFIG_GROUP_NAME,
	                       PRECONNECT_BACKLOG_KEY,
	                       DEFAULT_PRECONNECT_BACKLOG);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      MAX_DEPTH_MESSAGE_QUEUE_KEY,
	                      DEFAULT_MAX_DEPTH_MESSAGE_QUEUE);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      QUEUE_RESUME_OVERHEAD_KEY,
	                      DEFAULT_QUEUE_RESUME_OVERHEAD);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      MAX_STARVATION_LATENCY_KEY,
	                      DEFAULT_MAX_STARVATION_LATENCY);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      RESOLVE_ROUTE_TIMEOUT_MS_KEY,
	                      DEFAULT_RESOLVE_ROUTE_TIMEOUT_MS);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      RESOLVE_ADDR_TIMEOUT_MS_KEY,
	                      DEFAULT_RESOLVE_ADDR_TIMEOUT_MS);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      INACTIVE_SERVER_TIMEOUT_SEC_KEY,
	                      DEFAULT_INACTIVE_SERVER_TIMEOUT_SEC);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      SHUTDOWN_CHECK_INTERVAL_MS_KEY,
	                      DEFAULT_SHUTDOWN_CHECK_INTERVAL_MS);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      SIGNAL_RECEIVE_MAX_POSTED_KEY,
	                      DEFAULT_SIGNAL_RECEIVE_MAX_POSTED);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      SIGNAL_RECEIVE_MIN_ACK_PART_KEY,
	                      DEFAULT_SIGNAL_RECEIVE_MIN_ACK_PART);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      RDMA_READ_MAX_POSTED_KEY,
	                      DEFAULT_RDMA_READ_MAX_POSTED);
	g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
	                      RDMA_READ_MIN_ACK_PART_KEY,
	                      DEFAULT_RDMA_READ_MIN_ACK_PART);
	gchar *result = g_key_file_to_data(kf, NULL, NULL);
	g_key_file_free(kf);
	return result;
}

char *
config_vysmaw_base(void)
{
	char *dcfg = default_config_vysmaw();
	char *fcfg = load_config(VYSMAW_CONFIG_PATH, NULL);
	char *result = g_strjoin("\n", dcfg, fcfg, NULL);
	g_free(fcfg);
	g_free(dcfg);
	return result;
}

static guint64
parse_uint64(GKeyFile *kf, const gchar *key,
             struct vysmaw_configuration *config)
{
	GError *err = NULL;
	guint64 result =
		g_key_file_get_uint64(kf, VYSMAW_CONFIG_GROUP_NAME, key, &err);
	if (err != NULL) {
		MSG_ERROR(&(config->error_record), -1,
		          "Failed to parse '%s' field: %s",
		          key, err->message);
		g_error_free(err);
	}
	return result;
}

static gboolean
parse_boolean(GKeyFile *kf, const gchar *key,
              struct vysmaw_configuration *config)
{
	GError *err = NULL;
	gboolean result =
		g_key_file_get_boolean(kf, VYSMAW_CONFIG_GROUP_NAME, key, &err);
	if (err != NULL) {
		MSG_ERROR(&(config->error_record), -1,
		          "Failed to parse '%s' field: %s",
		          key, err->message);
		g_error_free(err);
	}
	return result;
}

static gdouble
parse_double(GKeyFile *kf, const gchar *key,
             struct vysmaw_configuration *config)
{
	GError *err = NULL;
	gdouble result =
		g_key_file_get_double(kf, VYSMAW_CONFIG_GROUP_NAME, key, &err);
	if (err != NULL) {
		MSG_ERROR(&(config->error_record), -1,
		          "Failed to parse '%s' field: %s",
		          key, err->message);
		g_error_free(err);
	}
	return result;
}

void
init_from_key_file_vysmaw(GKeyFile *kf, struct vysmaw_configuration *config)
{
	/* vys group configuration */
	struct vys_configuration vys_cfg = {
		.error_record = NULL
	};
	init_from_key_file_vys(kf, &vys_cfg);
	if (vys_cfg.error_record == NULL)
		g_strlcpy(config->signal_multicast_address,
		          vys_cfg.signal_multicast_address,
		          sizeof(config->signal_multicast_address));
	else
		config->error_record = vys_error_record_concat(
			vys_cfg.error_record, config->error_record);

	/* vysmaw group configuration */
	config->spectrum_buffer_pool_size =
		parse_uint64(kf, SPECTRUM_BUFFER_POOL_SIZE_KEY, config);
	config->single_spectrum_buffer_pool =
		parse_boolean(kf, SINGLE_SPECTRUM_BUFFER_POOL_KEY, config);
	config->max_spectrum_buffer_size =
		parse_uint64(kf, MAX_SPECTRUM_BUFFER_SIZE_KEY, config);
	config->signal_message_pool_size =
		parse_uint64(kf, SIGNAL_MESSAGE_POOL_SIZE_KEY, config);
	config->eager_connect =
		parse_boolean(kf, EAGER_CONNECT_KEY, config);
	config->eager_connect_idle_sec =
		parse_double(kf, EAGER_CONNECT_IDLE_SEC_KEY, config);
	config->preconnect_backlog =
		parse_boolean(kf, PRECONNECT_BACKLOG_KEY, config);
	config->max_depth_message_queue =
		parse_uint64(kf, MAX_DEPTH_MESSAGE_QUEUE_KEY, config);
	config->queue_resume_overhead =
		parse_uint64(kf, QUEUE_RESUME_OVERHEAD_KEY, config);
	config->max_starvation_latency =
		parse_uint64(kf, MAX_STARVATION_LATENCY_KEY, config);
	config->resolve_route_timeout_ms =
		parse_uint64(kf, RESOLVE_ROUTE_TIMEOUT_MS_KEY, config);
	config->resolve_addr_timeout_ms =
		parse_uint64(kf, RESOLVE_ADDR_TIMEOUT_MS_KEY, config);
	config->inactive_server_timeout_sec =
		parse_uint64(kf, INACTIVE_SERVER_TIMEOUT_SEC_KEY, config);
	config->shutdown_check_interval_ms =
		parse_uint64(kf, SHUTDOWN_CHECK_INTERVAL_MS_KEY, config);
	config->signal_receive_max_posted =
		parse_uint64(kf, SIGNAL_RECEIVE_MAX_POSTED_KEY, config);
	config->signal_receive_min_ack_part =
		parse_uint64(kf, SIGNAL_RECEIVE_MIN_ACK_PART_KEY, config);
	config->rdma_read_max_posted =
		parse_uint64(kf, RDMA_READ_MAX_POSTED_KEY, config);
	config->rdma_read_min_ack_part =
		parse_uint64(kf, RDMA_READ_MIN_ACK_PART_KEY, config);
}

vysmaw_handle
handle_ref(vysmaw_handle handle)
{
	g_atomic_int_inc(&(handle->refcount));
	return handle;
}

void
handle_unref(vysmaw_handle handle)
{
	if (g_atomic_int_dec_and_test(&handle->refcount)) {
		if (handle->signal_receiver_thread != NULL)
			g_thread_join(handle->signal_receiver_thread);
		if (handle->spectrum_selector_thread != NULL)
			g_thread_join(handle->spectrum_selector_thread);
		if (handle->spectrum_reader_thread != NULL)
			g_thread_join(handle->spectrum_reader_thread);

		MUTEX_CLEAR(handle->gate.mtx);
		COND_CLEAR(handle->gate.cond);

		struct consumer *c = handle->consumers;
		for (unsigned i = 0; i < handle->num_consumers; ++i) {
			message_queue_unref(&c->queue);
			g_array_free(c->pass_filter_array, TRUE);
			++c;
		}
		g_free(handle->consumers);

		if (handle->config.single_spectrum_buffer_pool) {
			spectrum_buffer_pool_unref(handle->pool);
		} else {
			spectrum_buffer_pool_collection_free(handle->pool_collection);
			MUTEX_CLEAR(handle->pool_collection_mtx);
		}

		MUTEX_CLEAR(handle->mtx);
	}
}

GSList *
all_consumers(vysmaw_handle handle)
{
	GSList *result = NULL;
	struct consumer *consumer = handle->consumers;
	for (unsigned i = handle->num_consumers; i > 0; --i) {
		result = g_slist_prepend(result, consumer);
		++consumer;
	}
	return result;
}

struct vysmaw_message *
message_new(vysmaw_handle handle, enum vysmaw_message_type typ)
{
	struct vysmaw_message *result = g_slice_new(struct vysmaw_message);
	result->refcount = 1;
	result->handle = handle_ref(handle);
	result->typ = typ;
	return result;
}

struct vysmaw_message *
data_buffer_starvation_message_new(vysmaw_handle handle,
                                   unsigned num_unavailable)
{
	struct vysmaw_message *result =
		message_new(handle, VYSMAW_MESSAGE_DATA_BUFFER_STARVATION);
	result->content.num_data_buffers_unavailable =
		handle->num_data_buffers_unavailable;
	return result;
}

struct vysmaw_message *
signal_buffer_starvation_message_new(vysmaw_handle handle,
                                     unsigned num_unavailable)
{
	struct vysmaw_message *result =
		message_new(handle, VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION);
	result->content.num_signal_buffers_unavailable =
		handle->num_signal_buffers_unavailable;
	return result;
}

struct vysmaw_message *
digest_failure_message_new(vysmaw_handle handle,
                           const struct vysmaw_data_info *info)
{
	struct vysmaw_message *result =
		message_new(handle, VYSMAW_MESSAGE_DIGEST_FAILURE);
	result->content.digest_failure = *info;
	return result;
}

struct vysmaw_message *
end_message_new(vysmaw_handle handle, struct vysmaw_result *rc)
{
	/* this steals ownership of rc->syserr_desc */
	struct vysmaw_message *result = message_new(handle, VYSMAW_MESSAGE_END);
	memcpy(&result->content.result, rc, sizeof(*rc));
	rc->syserr_desc = NULL;
	return result;
}

struct vysmaw_message *
queue_overflow_message_new(vysmaw_handle handle, unsigned num_overflow)
{
	struct vysmaw_message *result =
		message_new(handle, VYSMAW_MESSAGE_QUEUE_OVERFLOW);
	result->content.num_overflow = num_overflow;
	return result;
}

struct vysmaw_message *
signal_receive_failure_message_new(vysmaw_handle handle,
                                   enum ibv_wc_status status)
{
	struct vysmaw_message *result =
		message_new(handle, VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE);
	g_strlcpy(result->content.signal_receive_status, ibv_wc_status_str(status),
	          sizeof(result->content.signal_receive_status));
	return result;
}

void
post_msg(vysmaw_handle handle, struct vysmaw_message *msg)
{
	MUTEX_LOCK(handle->mtx);
	GSList *consumers = all_consumers(handle);
	message_queues_push_unlocked(msg, consumers);
	MUTEX_UNLOCK(handle->mtx);
	g_slist_free(consumers);
}

void
post_data_buffer_starvation(vysmaw_handle handle)
{
	struct vysmaw_message *msg =
		data_buffer_starvation_message_new(
			handle, handle->num_data_buffers_unavailable);
	post_msg(handle, msg);
	handle->num_data_buffers_unavailable = 0;
}

void
post_signal_buffer_starvation(vysmaw_handle handle)
{
	struct vysmaw_message *msg =
		signal_buffer_starvation_message_new(
			handle, handle->num_signal_buffers_unavailable);
	post_msg(handle, msg);
	handle->num_signal_buffers_unavailable = 0;
}

void
post_signal_receive_failure(vysmaw_handle handle, enum ibv_wc_status status)
{
	struct vysmaw_message *msg =
		signal_receive_failure_message_new(handle, status);
	post_msg(handle, msg);
}

vysmaw_message_queue
message_queue_ref(vysmaw_message_queue queue)
{
	g_async_queue_ref(queue->q);
	return queue;
}

void
message_queue_unref(vysmaw_message_queue queue)
{
	g_async_queue_unref(queue->q);
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_new(size_t buffer_size, size_t num_buffers)
{
	struct spectrum_buffer_pool *result =
		g_new(struct spectrum_buffer_pool, 1);
	result->refcount = 1;
	result->pool = buffer_pool_new(num_buffers, buffer_size);
	return result;
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_ref(struct spectrum_buffer_pool *pool)
{
	g_atomic_int_inc(&pool->refcount);
	return pool;
}

void
spectrum_buffer_pool_unref(struct spectrum_buffer_pool *buffer_pool)
{
	if (g_atomic_int_dec_and_test(&buffer_pool->refcount)) {
		buffer_pool_free(buffer_pool->pool);
		g_free(buffer_pool);
	}
}

void *
spectrum_buffer_pool_pop(struct spectrum_buffer_pool *buffer_pool)
{
	spectrum_buffer_pool_ref(buffer_pool);
	void *result = buffer_pool_pop(buffer_pool->pool);
	if (result == NULL) spectrum_buffer_pool_unref(buffer_pool);
	return result;
}

void
spectrum_buffer_pool_push(struct spectrum_buffer_pool *buffer_pool,
                          void *buffer)
{
	buffer_pool_push(buffer_pool->pool, buffer);
	spectrum_buffer_pool_unref(buffer_pool);
}

int
compare_pool_buffer_sizes(const void *a, const void *b, void *unused)
{
	const struct spectrum_buffer_pool *pa = a;
	const struct spectrum_buffer_pool *pb = b;
	return ((pa->pool->buffer_size < pb->pool->buffer_size)
	        ? -1
	        : ((pa->pool->buffer_size > pb->pool->buffer_size) ? 1 : 0));
}

spectrum_buffer_pool_collection
spectrum_buffer_pool_collection_new(void)
{
	return g_sequence_new((GDestroyNotify)spectrum_buffer_pool_unref);
}

void
spectrum_buffer_pool_collection_free(
	spectrum_buffer_pool_collection collection)
{
	g_sequence_free(collection);
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_collection_add(
	spectrum_buffer_pool_collection collection,
	size_t buffer_size,
	size_t num_buffers)
{
	struct spectrum_buffer_pool *pool =
		spectrum_buffer_pool_new(buffer_size, num_buffers);
	g_sequence_insert_sorted(collection, pool, compare_pool_buffer_sizes, NULL);
	return pool;
}

GSequenceIter *
spectrum_buffer_pool_collection_lookup_iter(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
{
	struct buffer_pool b = {
		.buffer_size = buffer_size
	};
	struct spectrum_buffer_pool s = {
		.pool = &b
	};
	return g_sequence_lookup(
		collection, &s, (GCompareDataFunc)compare_pool_buffer_sizes, NULL);
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_collection_lookup(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
{
	GSequenceIter *iter =
		spectrum_buffer_pool_collection_lookup_iter(
			collection, buffer_size);
	return ((iter == NULL) ? NULL : g_sequence_get(iter));
}

void
spectrum_buffer_pool_collection_remove(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
{
	GSequenceIter *iter =
		spectrum_buffer_pool_collection_lookup_iter(
			collection, buffer_size);
	if (iter != NULL) g_sequence_remove(iter);
}

void *
new_valid_buffer_from_collection(vysmaw_handle handle, size_t buffer_size,
                                 pool_id_t *pool_id)
{
	MUTEX_LOCK(handle->pool_collection_mtx);
	struct spectrum_buffer_pool *pool =
		spectrum_buffer_pool_collection_lookup(
			handle->pool_collection, buffer_size);
	if (G_UNLIKELY(pool == NULL)) {
		size_t num_buffers =
			handle->config.spectrum_buffer_pool_size / buffer_size;
		pool = spectrum_buffer_pool_collection_add(
			handle->pool_collection, buffer_size, num_buffers);
	}
	void *result = spectrum_buffer_pool_pop(pool);
	MUTEX_UNLOCK(handle->pool_collection_mtx);
	*pool_id = pool;
	return result;
}

void *
new_valid_buffer_from_pool(vysmaw_handle handle, size_t buffer_size,
                           pool_id_t *pool_id)
{
	void *buffer = NULL;
	struct spectrum_buffer_pool *pool = handle->pool;
	if (buffer_size <= pool->pool->buffer_size)
		buffer = spectrum_buffer_pool_pop(pool);
	*pool_id = pool;
	return buffer;
}

void
message_queue_force_push_one_unlocked(struct vysmaw_message *msg,
                                      vysmaw_message_queue queue)
{
	/* messages on the queue maintain a reference to the queue to facilitate
	 * automatic queue reclamation */
	message_queue_ref(queue);
	queue->depth++;
	g_async_queue_push_unlocked(queue->q, message_ref(msg));
}

void
message_queue_push_one_unlocked(struct vysmaw_message *msg,
                                struct consumer *consumer)
{
	/* adjust max depth to accommodate overhead */
	unsigned max_depth;
	if (G_LIKELY(msg->typ != VYSMAW_MESSAGE_END)) {
		max_depth = msg->handle->config.max_depth_message_queue;
		if (consumer->queue.num_overflow > 0)
			max_depth -= msg->handle->config.queue_resume_overhead + 1;
	} else {
		max_depth = UINT_MAX;
	}

	if (consumer->queue.depth < max_depth) {
		if (consumer->queue.num_overflow > 0) {
			struct vysmaw_message *overflow_msg =
				queue_overflow_message_new(
					msg->handle, consumer->queue.num_overflow);
			message_queue_force_push_one_unlocked(
				overflow_msg, &consumer->queue);
			consumer->queue.num_overflow = 0;
		}
		message_queue_force_push_one_unlocked(msg, &consumer->queue);
	} else {
		consumer->queue.num_overflow++;
	}
}

void
begin_shutdown(vysmaw_handle handle, struct vysmaw_result *rc)
{
	MUTEX_LOCK(handle->mtx);
	handle->in_shutdown = true;
	handle->result = rc;
	MUTEX_UNLOCK(handle->mtx);
}

void
get_shutdown_parameters(vysmaw_handle handle, bool *in_shutdown,
                        struct vysmaw_result **result)
{
	MUTEX_LOCK(handle->mtx);
	*in_shutdown = handle->in_shutdown;
	*result = handle->result;
	MUTEX_UNLOCK(handle->mtx);
}

struct spectrum_buffer_pool *
lookup_buffer_pool_from_collection(struct vysmaw_message *message)
{
	g_assert(message->typ == VYSMAW_MESSAGE_VALID_BUFFER);
	return spectrum_buffer_pool_collection_lookup(
		message->handle->pool_collection,
		spectrum_size(&message->content.valid_buffer.info));
}

struct spectrum_buffer_pool *
lookup_buffer_pool_from_pool(struct vysmaw_message *message)
{
	g_assert(message->typ == VYSMAW_MESSAGE_VALID_BUFFER);
	size_t buffer_size = spectrum_size(&message->content.valid_buffer.info);
	return ((buffer_size <= message->handle->pool->pool->buffer_size)
	        ? message->handle->pool
	        : NULL);
}

GSList *
buffer_pool_list_from_collection(vysmaw_handle handle)
{
	MUTEX_LOCK(handle->pool_collection_mtx);
	GSequenceIter *iter = g_sequence_get_begin_iter(handle->pool_collection);
	GSList *result = NULL;
	while (!g_sequence_iter_is_end(iter)) {
		result = g_slist_prepend(result, g_sequence_get(iter));
		iter = g_sequence_iter_next(iter);
	}
	MUTEX_UNLOCK(handle->pool_collection_mtx);
	return result;
}

GSList *
buffer_pool_list_from_pool(vysmaw_handle handle)
{
	return g_slist_prepend(NULL, handle->pool);
}

void
init_consumer(vysmaw_spectrum_filter filter, void *user_data,
              vysmaw_message_queue *queue, GArray *consumers)
{
	struct consumer consumer = {
		.queue = {
			.q = g_async_queue_new(),
			.depth = 0,
			.num_overflow = 0
		},
		.spectrum_filter_fn = filter,
		.pass_filter_array = g_array_new(FALSE, FALSE, sizeof(bool)),
		.user_data = user_data
	};
	g_array_append_val(consumers, consumer);
	*queue =
		&((&g_array_index(consumers, struct consumer, consumers->len - 1))
		  ->queue);
}

void
init_signal_receiver(vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
                     struct buffer_pool **signal_msg_buffers,
                     unsigned *signal_msg_num_spectra, int loop_fd)
{
	struct signal_receiver_context *context =
		g_new0(struct signal_receiver_context, 1);
	context->handle = handle_ref(handle);
	context->loop_fd = loop_fd;
	context->signal_msg_queue = g_async_queue_ref(signal_msg_queue);
	handle->signal_receiver_thread =
		THREAD_NEW("signal_receiver", (GThreadFunc)signal_receiver, context);
	while (!handle->gate.signal_receiver_ready)
		COND_WAIT(handle->gate.cond, handle->gate.mtx);
	*signal_msg_buffers = context->signal_msg_buffers;
	*signal_msg_num_spectra = context->signal_msg_num_spectra;
}

void
init_spectrum_selector(vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
                       GAsyncQueue *read_request_queue,
                       struct buffer_pool *signal_msg_buffers,
                       unsigned signal_msg_num_spectra)
{
	struct spectrum_selector_context *context =
		g_new(struct spectrum_selector_context, 1);
	context->handle = handle_ref(handle);
	context->signal_msg_queue = g_async_queue_ref(signal_msg_queue);
	context->read_request_queue = g_async_queue_ref(read_request_queue);
	context->signal_msg_buffers = signal_msg_buffers;
	context->signal_msg_num_spectra = signal_msg_num_spectra;
	handle->spectrum_selector_thread =
		THREAD_NEW("spectrum_selector", (GThreadFunc)spectrum_selector,
		           context);
}

void
init_spectrum_reader(vysmaw_handle handle, GAsyncQueue *read_request_queue,
                     struct buffer_pool *signal_msg_buffers,
                     unsigned signal_msg_num_spectra, int loop_fd)
{
	struct spectrum_reader_context *context =
		g_new(struct spectrum_reader_context, 1);
	context->handle = handle_ref(handle);
	context->loop_fd = loop_fd;
	context->signal_msg_buffers = signal_msg_buffers;
	context->signal_msg_num_spectra = signal_msg_num_spectra;
	context->read_request_queue = g_async_queue_ref(read_request_queue);
	handle->spectrum_reader_thread =
		THREAD_NEW("spectrum_reader", (GThreadFunc)spectrum_reader,
		           context);
}

int
init_service_threads(vysmaw_handle handle)
{

	MUTEX_LOCK(handle->gate.mtx);

	int loop_fds[2];
	int rc;
#ifdef _GNU_SOURCE
	rc = pipe2(loop_fds, O_NONBLOCK);
#else
	rc = pipe(loop_fds);
	if (rc == 0) rc = set_nonblocking(loop_fds[0]);
	if (rc == 0) rc = set_nonblocking(loop_fds[1]);
#endif
	if (rc != 0) {
		MSG_ERROR((struct vys_error_record **)(&(handle->config.error_record)),
		          errno,
		          "Failed to create service thread loop pipe: %s",
		          strerror(errno));
		return rc;
	}

	struct buffer_pool *signal_msg_buffers;
	unsigned signal_msg_num_spectra;
	GAsyncQueue *signal_msg_queue = g_async_queue_new();
	init_signal_receiver(handle, signal_msg_queue, &signal_msg_buffers,
	                     &signal_msg_num_spectra, loop_fds[0]);

	GAsyncQueue *read_request_queue = g_async_queue_new();
	init_spectrum_selector(handle, signal_msg_queue, read_request_queue,
	                       signal_msg_buffers, signal_msg_num_spectra);

	init_spectrum_reader(handle, read_request_queue, signal_msg_buffers,
	                     signal_msg_num_spectra, loop_fds[1]);

	MUTEX_UNLOCK(handle->gate.mtx);

	g_async_queue_unref(signal_msg_queue);
	g_async_queue_unref(read_request_queue);

	return 0;
}

struct vysmaw_message *
message_ref(struct vysmaw_message *message)
{
	g_atomic_int_inc(&message->refcount);
	return message;
}

struct vysmaw_message *
message_queue_pop(vysmaw_message_queue queue)
{
	g_async_queue_lock(queue->q);
	struct vysmaw_message *result = g_async_queue_pop_unlocked(queue->q);
	queue->depth--;
	g_async_queue_unlock(queue->q);
	message_queue_unref(queue); // release message's queue reference
	return result;
}

struct data_path_message *
data_path_message_new(unsigned max_spectra_per_signal)
{
	size_t message_size =
		sizeof(struct data_path_message)
		+ max_spectra_per_signal * sizeof(GSList *);
	struct data_path_message *result = g_slice_alloc0(message_size);
	result->message_size = message_size;
	return result;
}

void
data_path_message_free(struct data_path_message *msg)
{
	if (msg->typ == DATA_PATH_SIGNAL_MSG) {
		size_t consumer_offset = offsetof(struct data_path_message, consumers);
		GSList **l = (GSList **)((void *)msg + consumer_offset);
		while (consumer_offset < msg->message_size) {
			if (*l != NULL) g_slist_free(*l);
			++l;
			consumer_offset += sizeof(GSList *);
		}
	} else if (msg->typ == DATA_PATH_END) {
		vys_error_record_free(msg->error_record);
	}
	g_slice_free1(msg->message_size, msg);
}

struct vysmaw_message *
valid_buffer_message_new(vysmaw_handle handle,
                         const struct vysmaw_data_info *info,
                         pool_id_t *pool_id)
{
	size_t buffer_size = spectrum_size(info);
	void *buffer = handle->new_valid_buffer_fn(handle, buffer_size, pool_id);
	struct vysmaw_message *result = NULL;
	if (buffer != NULL) {
		if (handle->num_data_buffers_unavailable > 0)
			post_data_buffer_starvation(handle);
		result = message_new(handle, VYSMAW_MESSAGE_VALID_BUFFER);
		result->content.valid_buffer.info = *info;
		result->content.valid_buffer.buffer_size = buffer_size;
		result->content.valid_buffer.buffer = buffer;
	} else {
		mark_data_buffer_starvation(handle);
	}
	return result;
}

void
message_queues_push_unlocked(struct vysmaw_message *msg, GSList *consumers)
{
	while (consumers != NULL) {
		message_queue_push_one_unlocked(
			message_ref(msg), (struct consumer *)(consumers->data));
		consumers = g_slist_next(consumers);
	}
	vysmaw_message_unref(msg);
}

void
message_queues_push(struct vysmaw_message *msg, GSList *consumers)
{
	MUTEX_LOCK(msg->handle->mtx);
	message_queues_push_unlocked(msg, consumers);
	MUTEX_UNLOCK(msg->handle->mtx);
}

void
mark_data_buffer_starvation(vysmaw_handle handle)
{
	handle->num_data_buffers_unavailable++;
	if (handle->num_data_buffers_unavailable
	    >= handle->config.max_starvation_latency)
		post_data_buffer_starvation(handle);
}

void
mark_signal_buffer_starvation(vysmaw_handle handle)
{
	handle->num_signal_buffers_unavailable++;
	if (handle->num_signal_buffers_unavailable
	    >= handle->config.max_starvation_latency)
		post_signal_buffer_starvation(handle);
}

void
mark_signal_receive_failure(vysmaw_handle handle, enum ibv_wc_status status)
{
	post_signal_receive_failure(handle, status);
}

static void
vysmaw_message_release_buffer(struct vysmaw_message *message)
{
	if (message->typ == VYSMAW_MESSAGE_VALID_BUFFER
	    && message->content.valid_buffer.buffer != NULL) {
		struct spectrum_buffer_pool *pool =
			message->handle->lookup_buffer_pool_fn(message);
		if (G_LIKELY(pool != NULL)) {
			spectrum_buffer_pool_push(
				pool, message->content.valid_buffer.buffer);
		} else {
			struct vysmaw_result *rc = g_new(struct vysmaw_result, 1);
			rc->code = VYSMAW_ERROR_BUFFPOOL;
			rc->syserr_desc = g_strdup("");
			begin_shutdown(message->handle, rc);
		}
	}
}

static void
vysmaw_message_free_syserr_desc(struct vysmaw_message *message)
{
	if (message->typ == VYSMAW_MESSAGE_END &&
	    message->content.result.syserr_desc != NULL)
		g_free(message->content.result.syserr_desc);
}

void
vysmaw_message_free_resources(struct vysmaw_message *message)
{
	vysmaw_message_release_buffer(message);
	vysmaw_message_free_syserr_desc(message);
	handle_unref(message->handle);
}

GHashTable *
register_spectrum_buffer_pools(vysmaw_handle handle, struct rdma_cm_id *id,
                               struct vys_error_record **error_record)
{
	GHashTable *result =
		g_hash_table_new(g_direct_hash, g_direct_equal);
	GSList *sb_pool_node = handle->list_buffer_pools_fn(handle);
	int rc = 0;
	while (result != NULL && sb_pool_node != NULL) {
		if (G_LIKELY(rc == 0)) {
			struct spectrum_buffer_pool *sb_pool = sb_pool_node->data;
			struct ibv_mr *mr = rdma_reg_msgs(
				id, sb_pool->pool->pool, sb_pool->pool->pool_size);
			if (G_LIKELY(mr != NULL)) {
				g_hash_table_insert(result, sb_pool, mr);
			} else {
				VERB_ERR(error_record, errno, "rdma_reg_msgs");
				rc = -1;
				GList *keys = g_hash_table_get_keys(result);
				while (keys != NULL) {
					int rc1 =
						rdma_dereg_mr(
							(struct ibv_mr *)g_hash_table_lookup(
								result, keys->data));
					if (G_UNLIKELY(rc1 != 0))
						VERB_ERR(error_record, errno, "rdma_dereg_mr");
				}
				g_hash_table_destroy(result);
				result = NULL;
			}
		}
		sb_pool_node = g_slist_delete_link(sb_pool_node, sb_pool_node);
	}
	return result;
}

unsigned
sockaddr_hash(const struct sockaddr_in *sockaddr)
{
	return (unsigned)sockaddr->sin_port +
		43 * (unsigned)sockaddr->sin_addr.s_addr;
}

bool
sockaddr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
	return (a->sin_port == b->sin_port &&
	        a->sin_addr.s_addr == b->sin_addr.s_addr);
}

struct sockaddr_in *
new_sockaddr_key(const struct sockaddr_in *sockaddr)
{
	struct sockaddr_in *result = g_slice_new0(struct sockaddr_in);
	memcpy(result, sockaddr, sizeof(*result));
	return result;
}

void
free_sockaddr_key(struct sockaddr_in *sockaddr)
{
	g_slice_free(struct sockaddr_in, sockaddr);
}

void
convert_valid_to_digest_failure(struct vysmaw_message *message)
{
	g_assert(message->typ == VYSMAW_MESSAGE_VALID_BUFFER);
	vysmaw_message_release_buffer(message);
	message->typ = VYSMAW_MESSAGE_DIGEST_FAILURE;
	if (offsetof(struct vysmaw_message, content.digest_failure) !=
	    offsetof(struct vysmaw_message, content.valid_buffer.info))
		memmove(&message->content.digest_failure,
		        &message->content.valid_buffer.info,
		        sizeof(message->content.valid_buffer.info));
}

void
convert_valid_to_rdma_read_failure(struct vysmaw_message *message,
                                   enum ibv_wc_status status)
{
	g_assert(message->typ == VYSMAW_MESSAGE_VALID_BUFFER);
	vysmaw_message_release_buffer(message);
	message->typ = VYSMAW_MESSAGE_RDMA_READ_FAILURE;
	g_strlcpy(message->content.rdma_read_status, ibv_wc_status_str(status),
	          sizeof(message->content.rdma_read_status));
}

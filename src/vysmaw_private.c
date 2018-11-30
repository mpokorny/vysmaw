/* -*- mode: c; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
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
#define DEFAULT_MAX_SPECTRUM_BUFFER_SIZE (8 * (1 << 10))
#define DEFAULT_SPECTRUM_BUFFER_POOL_MIN_IDLE_LIFETIME_SEC 30
#define DEFAULT_SIGNAL_MESSAGE_RECEIVE_MIN_POSTED 4000
#define DEFAULT_SIGNAL_MESSAGE_RECEIVE_MAX_POSTED 8000
#define DEFAULT_SIGNAL_MESSAGE_POOL_OVERHEAD_FACTOR 2
#define DEFAULT_SIGNAL_MESSAGE_RECEIVE_QUEUE_UNDERFLOW_LEVEL 100
#define DEFAULT_EAGER_CONNECT true
#define DEFAULT_EAGER_CONNECT_IDLE_SEC 1
#define DEFAULT_PRECONNECT_BACKLOG true
#define DEFAULT_MESSAGE_QUEUE_ALERT_DEPTH 4000
#define DEFAULT_MESSAGE_QUEUE_ALERT_INTERVAL 10000
#define DEFAULT_MAX_STARVATION_LATENCY 100
#define DEFAULT_MAX_VERSION_MISMATCH_LATENCY 1000
#define DEFAULT_RESOLVE_ROUTE_TIMEOUT_MS 1000
#define DEFAULT_RESOLVE_ADDR_TIMEOUT_MS 1000
#define DEFAULT_INACTIVE_SERVER_TIMEOUT_SEC (60 * 60 * 12)
#define DEFAULT_SHUTDOWN_CHECK_INTERVAL_MS 1000
#define DEFAULT_SIGNAL_RECEIVE_MIN_ACK_PART 10
#define DEFAULT_RDMA_READ_MAX_POSTED 1000
#define DEFAULT_RDMA_READ_MIN_ACK 16

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
                        SPECTRUM_BUFFER_POOL_MIN_IDLE_LIFETIME_SEC_KEY,
                        DEFAULT_SPECTRUM_BUFFER_POOL_MIN_IDLE_LIFETIME_SEC);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        MAX_SPECTRUM_BUFFER_SIZE_KEY,
                        DEFAULT_MAX_SPECTRUM_BUFFER_SIZE);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        SIGNAL_MESSAGE_RECEIVE_MIN_POSTED_KEY,
                        DEFAULT_SIGNAL_MESSAGE_RECEIVE_MIN_POSTED);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        SIGNAL_MESSAGE_RECEIVE_MAX_POSTED_KEY,
                        DEFAULT_SIGNAL_MESSAGE_RECEIVE_MAX_POSTED);
  g_key_file_set_double(kf, VYSMAW_CONFIG_GROUP_NAME,
                        SIGNAL_MESSAGE_POOL_OVERHEAD_FACTOR_KEY,
                        DEFAULT_SIGNAL_MESSAGE_POOL_OVERHEAD_FACTOR);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        SIGNAL_MESSAGE_RECEIVE_QUEUE_UNDERFLOW_LEVEL_KEY,
                        DEFAULT_SIGNAL_MESSAGE_RECEIVE_QUEUE_UNDERFLOW_LEVEL);
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
                        MESSAGE_QUEUE_ALERT_DEPTH_KEY,
                        DEFAULT_MESSAGE_QUEUE_ALERT_DEPTH);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        MESSAGE_QUEUE_ALERT_INTERVAL_KEY,
                        DEFAULT_MESSAGE_QUEUE_ALERT_INTERVAL);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        MAX_STARVATION_LATENCY_KEY,
                        DEFAULT_MAX_STARVATION_LATENCY);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        MAX_VERSION_MISMATCH_LATENCY_KEY,
                        DEFAULT_MAX_VERSION_MISMATCH_LATENCY);
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
                        SIGNAL_RECEIVE_MIN_ACK_PART_KEY,
                        DEFAULT_SIGNAL_RECEIVE_MIN_ACK_PART);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        RDMA_READ_MAX_POSTED_KEY,
                        DEFAULT_RDMA_READ_MAX_POSTED);
  g_key_file_set_uint64(kf, VYSMAW_CONFIG_GROUP_NAME,
                        RDMA_READ_MIN_ACK_KEY,
                        DEFAULT_RDMA_READ_MIN_ACK);
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
  config->spectrum_buffer_pool_min_idle_lifetime_sec =
    parse_uint64(kf, SPECTRUM_BUFFER_POOL_MIN_IDLE_LIFETIME_SEC_KEY,
                 config);
  config->max_spectrum_buffer_size =
    parse_uint64(kf, MAX_SPECTRUM_BUFFER_SIZE_KEY, config);
  config->signal_message_receive_min_posted =
    parse_uint64(kf, SIGNAL_MESSAGE_RECEIVE_MIN_POSTED_KEY, config);
  config->signal_message_receive_max_posted =
    parse_uint64(kf, SIGNAL_MESSAGE_RECEIVE_MAX_POSTED_KEY, config);
  config->signal_message_pool_overhead_factor =
    parse_double(kf, SIGNAL_MESSAGE_POOL_OVERHEAD_FACTOR_KEY, config);
  config->signal_message_pool_overhead_factor =
    MAX(config->signal_message_pool_overhead_factor, 1.0);
  config->signal_message_receive_queue_underflow_level =
    parse_uint64(kf, SIGNAL_MESSAGE_RECEIVE_QUEUE_UNDERFLOW_LEVEL_KEY,
                 config);
  config->eager_connect =
    parse_boolean(kf, EAGER_CONNECT_KEY, config);
  config->eager_connect_idle_sec =
    parse_double(kf, EAGER_CONNECT_IDLE_SEC_KEY, config);
  config->preconnect_backlog =
    parse_boolean(kf, PRECONNECT_BACKLOG_KEY, config);
  config->message_queue_alert_depth =
    parse_uint64(kf, MESSAGE_QUEUE_ALERT_DEPTH_KEY, config);
  config->message_queue_alert_interval =
    parse_uint64(kf, MESSAGE_QUEUE_ALERT_INTERVAL_KEY, config);
  config->max_starvation_latency =
    parse_uint64(kf, MAX_STARVATION_LATENCY_KEY, config);
  config->max_version_mismatch_latency =
    parse_uint64(kf, MAX_VERSION_MISMATCH_LATENCY_KEY, config);
  config->resolve_route_timeout_ms =
    parse_uint64(kf, RESOLVE_ROUTE_TIMEOUT_MS_KEY, config);
  config->resolve_addr_timeout_ms =
    parse_uint64(kf, RESOLVE_ADDR_TIMEOUT_MS_KEY, config);
  config->inactive_server_timeout_sec =
    parse_uint64(kf, INACTIVE_SERVER_TIMEOUT_SEC_KEY, config);
  config->shutdown_check_interval_ms =
    parse_uint64(kf, SHUTDOWN_CHECK_INTERVAL_MS_KEY, config);
  config->signal_receive_min_ack_part =
    parse_uint64(kf, SIGNAL_RECEIVE_MIN_ACK_PART_KEY, config);
  config->rdma_read_max_posted =
    parse_uint64(kf, RDMA_READ_MAX_POSTED_KEY, config);
  config->rdma_read_min_ack =
    parse_uint64(kf, RDMA_READ_MIN_ACK_KEY, config);
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
    GThread *self = g_thread_self();

    if (handle->signal_receiver_thread != NULL
        && handle->signal_receiver_thread != self)
      g_thread_join(handle->signal_receiver_thread);

    if (handle->spectrum_selector_thread != NULL
        && handle->spectrum_selector_thread != self)
      g_thread_join(handle->spectrum_selector_thread);

    if (handle->spectrum_reader_thread != NULL
        && handle->spectrum_reader_thread != self)
      g_thread_join(handle->spectrum_reader_thread);

    MUTEX_CLEAR(handle->gate.mtx);
    COND_CLEAR(handle->gate.cond);

    message_queue_unref(handle->consumer->queue);
    g_array_free(handle->consumer->pass_filter_array, TRUE);
    g_free(handle->consumer);

    if (handle->config.single_spectrum_buffer_pool) {
      REC_MUTEX_CLEAR(handle->pool_collection_mtx);
      spectrum_buffer_pool_unref(handle->pool);
    } else {
      spectrum_buffer_pool_collection_free(handle->pool_collection);
    }

    if (handle->header_pool != NULL)
      vys_buffer_pool_free(handle->header_pool);

    MUTEX_CLEAR(handle->mtx);
    g_free(handle);
  }
}

struct vysmaw_message *
message_new(vysmaw_handle handle, enum vysmaw_message_type typ)
{
  struct vysmaw_message *result;
  if (typ == VYSMAW_MESSAGE_SPECTRA) {
    result = g_slice_alloc(
      SIZEOF_VYSMAW_MESSAGE(handle->signal_msg_num_spectra));
    result->content.spectra.num_spectra = handle->signal_msg_num_spectra;
  } else {
    result = g_slice_new(struct vysmaw_message);
  }
  result->refcount = 1;
  result->handle = handle_ref(handle);
  result->typ = typ;
  return result;
}

struct vysmaw_message *
spectrum_buffer_starvation_message_new(vysmaw_handle handle,
                                       unsigned num_unavailable)
{
  struct vysmaw_message *result =
    message_new(handle, VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION);
  result->content.num_spectrum_buffers_unavailable =
    handle->num_spectrum_buffers_unavailable;
  return result;
}

struct vysmaw_message *
signal_receive_queue_underflow_message_new(vysmaw_handle handle)
{
  return message_new(handle, VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW);
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
queue_alert_message_new(vysmaw_handle handle, unsigned queue_depth)
{
  struct vysmaw_message *result =
    message_new(handle, VYSMAW_MESSAGE_QUEUE_ALERT);
  result->content.queue_depth = queue_depth;
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

struct vysmaw_message *
version_mismatch_message_new(vysmaw_handle handle, unsigned num_spectra,
                             unsigned mismatched_version)
{
  struct vysmaw_message *result =
    message_new(handle, VYSMAW_MESSAGE_VERSION_MISMATCH);
  result->content.num_spectra_mismatched_version = num_spectra;
  result->content.received_message_version = mismatched_version;
  return result;
}

void
post_msg(vysmaw_handle handle, struct vysmaw_message *msg)
{
  vysmaw_message_queue mq = handle->consumer->queue;
  message_queue_lock(mq);
  message_queue_push_one_unlocked(message_ref(msg), mq);
  if (G_UNLIKELY(
        mq->depth >= msg->handle->config.message_queue_alert_depth)) {
    mq->num_queued_in_alert =
      (mq->num_queued_in_alert + 1)
      % msg->handle->config.message_queue_alert_interval;
    if (G_UNLIKELY(mq->num_queued_in_alert == 0))
      message_queue_push_one_unlocked(
        queue_alert_message_new(msg->handle, mq->depth),
        mq);
  } else {
    mq->num_queued_in_alert = -1;
  }
  message_queue_unlock(mq);
  vysmaw_message_unref(msg);
}

void
post_spectrum_buffer_starvation(vysmaw_handle handle)
{
  struct vysmaw_message *msg =
    spectrum_buffer_starvation_message_new(
      handle, handle->num_spectrum_buffers_unavailable);
  post_msg(handle, msg);
  handle->num_spectrum_buffers_unavailable = 0;
}

void
post_signal_receive_failure(vysmaw_handle handle, enum ibv_wc_status status)
{
  struct vysmaw_message *msg =
    signal_receive_failure_message_new(handle, status);
  post_msg(handle, msg);
}

void
post_version_mismatch(vysmaw_handle handle)
{
  struct vysmaw_message *msg =
    version_mismatch_message_new(
      handle, handle->num_spectra_mismatched_version,
      handle->mismatched_version);
  post_msg(handle, msg);
  handle->num_spectra_mismatched_version = 0;
}

void
post_signal_receive_queue_underflow(vysmaw_handle handle)
{
  struct vysmaw_message *msg =
    signal_receive_queue_underflow_message_new(handle);
  post_msg(handle, msg);
}

vysmaw_message_queue
message_queue_new()
{
  vysmaw_message_queue result = g_new(struct _vysmaw_message_queue, 1);
  pthread_spin_init(&result->lock, PTHREAD_PROCESS_PRIVATE);
  result->refcount = 1;
  result->q = g_queue_new();
  result->depth = 0;
  result->num_queued_in_alert = -1;
  return result;
}

vysmaw_message_queue
message_queue_ref(vysmaw_message_queue queue)
{
  g_atomic_int_inc(&queue->refcount);
  return queue;
}

void
message_queue_unref(vysmaw_message_queue queue)
{
  if (g_atomic_int_dec_and_test(&queue->refcount)) {
    g_queue_free(queue->q);
    pthread_spin_destroy(&queue->lock);
    g_free(queue);
  }
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_new(size_t buffer_size, size_t num_buffers)
{
  struct spectrum_buffer_pool *result =
    g_new(struct spectrum_buffer_pool, 1);
  result->refcount = 1;
  result->inactive = FALSE;
  result->pool = vys_buffer_pool_new(num_buffers, buffer_size);
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
    vys_buffer_pool_free(buffer_pool->pool);
    g_free(buffer_pool);
  }
}

void *
spectrum_buffer_pool_pop(struct spectrum_buffer_pool *buffer_pool)
{
  buffer_pool->inactive = FALSE;
  void *result = vys_buffer_pool_pop(buffer_pool->pool);
  return result;
}

void
spectrum_buffer_pool_push(struct spectrum_buffer_pool *buffer_pool,
                          void *buffer)
{
  vys_buffer_pool_push(buffer_pool->pool, buffer);
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
  RecMutex *mtx,
  size_t buffer_size,
  size_t num_buffers)
{
  struct spectrum_buffer_pool *pool =
    spectrum_buffer_pool_new(buffer_size, num_buffers);
  REC_MUTEX_LOCK(*mtx);
  g_sequence_insert_sorted(collection, pool, compare_pool_buffer_sizes, NULL);
  REC_MUTEX_UNLOCK(*mtx);
  return pool;
}

GSequenceIter *
spectrum_buffer_pool_collection_lookup_iter(
  spectrum_buffer_pool_collection collection, RecMutex *mtx,
  size_t buffer_size)
{
  struct vys_buffer_pool b = {
    .buffer_size = buffer_size
  };
  struct spectrum_buffer_pool s = {
    .pool = &b
  };
  REC_MUTEX_LOCK(*mtx);
  GSequenceIter *result =
    g_sequence_lookup(
      collection, &s, (GCompareDataFunc)compare_pool_buffer_sizes, NULL);
  REC_MUTEX_UNLOCK(*mtx);
  return result;
}

struct spectrum_buffer_pool *
spectrum_buffer_pool_collection_lookup(
  spectrum_buffer_pool_collection collection, RecMutex *mtx,
  size_t buffer_size)
{
  REC_MUTEX_LOCK(*mtx);
  GSequenceIter *iter =
    spectrum_buffer_pool_collection_lookup_iter(
      collection, mtx, buffer_size);
  struct spectrum_buffer_pool *result =
    ((iter == NULL) ? NULL : g_sequence_get(iter));
  REC_MUTEX_UNLOCK(*mtx);
  return result;
}

void
spectrum_buffer_pool_collection_remove(
  spectrum_buffer_pool_collection collection, RecMutex *mtx,
  size_t buffer_size)
{
  REC_MUTEX_LOCK(*mtx);
  GSequenceIter *iter =
    spectrum_buffer_pool_collection_lookup_iter(
      collection, mtx, buffer_size);
  if (iter != NULL) g_sequence_remove(iter);
  REC_MUTEX_UNLOCK(*mtx);
}

void *
new_valid_buffer_from_collection(
  vysmaw_handle handle, struct rdma_cm_id *id, GHashTable *mrs,
  size_t buffer_size, pool_id_t *pool_id,
  struct vys_error_record **error_record)
{
  struct spectrum_buffer_pool *pool =
    spectrum_buffer_pool_collection_lookup(
      handle->pool_collection, &handle->pool_collection_mtx, buffer_size);
  if (G_UNLIKELY(pool == NULL)) {
    size_t num_buffers =
      handle->config.spectrum_buffer_pool_size / buffer_size;
    pool = spectrum_buffer_pool_collection_add(
      handle->pool_collection, &handle->pool_collection_mtx, buffer_size,
      num_buffers);
    int rc = register_one_spectrum_buffer_pool(
      pool, id, mrs, error_record);
    if (G_UNLIKELY(rc != 0)) pool = NULL;
  }
  void *result;
  if (G_LIKELY(pool != NULL)) {
    result = spectrum_buffer_pool_pop(pool);
    *pool_id = pool;
  } else {
    result = NULL;
  }
  return result;
}

void *
new_valid_buffer_from_pool(
  vysmaw_handle handle, struct rdma_cm_id *id, GHashTable *mrs,
  size_t buffer_size, pool_id_t *pool_id,
  struct vys_error_record **error_record)
{
  void *buffer = NULL;
  struct spectrum_buffer_pool *pool = handle->pool;
  if (G_LIKELY(buffer_size <= pool->pool->buffer_size))
    buffer = spectrum_buffer_pool_pop(pool);
  *pool_id = pool;
  return buffer;
}

void
message_queue_push_one_unlocked(struct vysmaw_message *msg,
                                vysmaw_message_queue queue)
{
  queue->depth++;
  g_queue_push_head(queue->q, msg);
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
get_buffer_pool(struct vysmaw_message *message)
{
  return message->handle->lookup_buffer_pool_fn(message);
}

struct spectrum_buffer_pool *
lookup_buffer_pool_from_collection(struct vysmaw_message *message)
{
  g_assert(message->typ == VYSMAW_MESSAGE_SPECTRA);
  return spectrum_buffer_pool_collection_lookup(
    message->handle->pool_collection, &message->handle->pool_collection_mtx,
    spectrum_buffer_size(&message->content.spectra.info));
}

struct spectrum_buffer_pool *
lookup_buffer_pool_from_pool(struct vysmaw_message *message)
{
  g_assert(message->typ == VYSMAW_MESSAGE_SPECTRA);
  size_t buff_size = spectrum_buffer_size(&message->content.spectra.info);
  return ((buff_size <= message->handle->pool->pool->buffer_size)
          ? message->handle->pool
          : NULL);
}

void
remove_idle_pools_from_pool(
  vysmaw_handle handle,
  void (*cb)(struct spectrum_buffer_pool *, struct vys_error_record **),
  struct vys_error_record **error_record)
{
  return; // no-op
}

void
remove_idle_pools_from_collection(
  vysmaw_handle handle,
  void (*cb)(struct spectrum_buffer_pool *, struct vys_error_record **),
  struct vys_error_record **error_record)
{
  spectrum_buffer_pool_collection pool_collection = handle->pool_collection;
  REC_MUTEX_LOCK(handle->pool_collection_mtx);
  GSequenceIter *iter = g_sequence_get_begin_iter(pool_collection);
  while (!g_sequence_iter_is_end(iter)) {
    struct spectrum_buffer_pool *pool = g_sequence_get(iter);
    if (G_UNLIKELY(pool->inactive)) {
      cb(pool, error_record);
      g_sequence_remove(iter);
    } else {
      pool->inactive = TRUE;
    }
    iter = g_sequence_iter_next(iter);
  }
  REC_MUTEX_UNLOCK(handle->pool_collection_mtx);
}

void
init_consumer(vysmaw_spectrum_filter filter, void *user_data,
              vysmaw_message_queue *queue, struct consumer *consumer)
{
  consumer->queue = message_queue_new();
  consumer->spectrum_filter_fn = filter;
  consumer->pass_filter_array = g_array_new(FALSE, FALSE, sizeof(bool));
  consumer->user_data = user_data;
  *queue = message_queue_ref(consumer->queue);
}

void
init_signal_receiver(vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
                     int loop_fd)
{
  struct signal_receiver_context *context =
    g_new0(struct signal_receiver_context, 1);
  context->handle = handle;
  context->loop_fd = loop_fd;
  context->signal_msg_queue = g_async_queue_ref(signal_msg_queue);
  handle->signal_receiver_thread =
    THREAD_NEW("signal_receiver", (GThreadFunc)signal_receiver, context);
  while (!handle->gate.signal_receiver_ready)
    COND_WAIT(handle->gate.cond, handle->gate.mtx);
}

void
init_spectrum_selector(vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
                       struct vys_async_queue *read_request_queue)
{
  struct spectrum_selector_context *context =
    g_new(struct spectrum_selector_context, 1);
  context->handle = handle;
  context->signal_msg_queue = g_async_queue_ref(signal_msg_queue);
  context->read_request_queue = vys_async_queue_ref(read_request_queue);
  handle->spectrum_selector_thread =
    THREAD_NEW("spectrum_selector", (GThreadFunc)spectrum_selector,
               context);
}

void
init_spectrum_reader(vysmaw_handle handle,
                     struct vys_async_queue *read_request_queue,
                     int loop_fd)
{
  struct spectrum_reader_context *context =
    g_new(struct spectrum_reader_context, 1);
  context->handle = handle;
  context->loop_fd = loop_fd;
  context->read_request_queue = vys_async_queue_ref(read_request_queue);
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

  GAsyncQueue *signal_msg_queue = g_async_queue_new();
  init_signal_receiver(handle, signal_msg_queue, loop_fds[0]);

  struct vys_async_queue *read_request_queue = vys_async_queue_new();
  init_spectrum_selector(handle, signal_msg_queue, read_request_queue);

  init_spectrum_reader(handle, read_request_queue, loop_fds[1]);

  MUTEX_UNLOCK(handle->gate.mtx);

  g_async_queue_unref(signal_msg_queue);
  vys_async_queue_unref(read_request_queue);

  return 0;
}

void
start_service_in_order(vysmaw_handle handle, service_type_t service)
{
  struct service_gate *gate = &handle->gate;

  MUTEX_LOCK(gate->mtx);
  switch (service) {
  case SIGNAL_RECEIVER:
    gate->signal_receiver_ready = true;
    break;
  case SPECTRUM_SELECTOR:
    gate->spectrum_selector_ready = true;
    break;
  case SPECTRUM_READER:
    gate->spectrum_reader_ready = true;
    break;
  }
  COND_BCAST(gate->cond);
  MUTEX_UNLOCK(gate->mtx);

#define WAIT_FOR_FLAG(flag)                     \
  G_STMT_START {                                \
    MUTEX_LOCK(gate->mtx);                      \
    while (!gate->flag)                         \
      COND_WAIT(gate->cond, gate->mtx);         \
    MUTEX_UNLOCK(gate->mtx);                    \
  } G_STMT_END

  WAIT_FOR_FLAG(spectrum_reader_ready);
  WAIT_FOR_FLAG(spectrum_selector_ready);
  WAIT_FOR_FLAG(signal_receiver_ready);

#undef WAIT_FOR_FLAG
}

struct vysmaw_message *
message_ref(struct vysmaw_message *message)
{
  g_atomic_int_inc(&message->refcount);
  return message;
}

struct data_path_message *
data_path_message_new(vysmaw_handle handle)
{
  return vys_buffer_pool_pop(handle->data_path_msg_pool);
}

void
data_path_message_free(vysmaw_handle handle, struct data_path_message *msg)
{
  if (msg->typ == DATA_PATH_END)
    vys_error_record_free(msg->error_record);
  vys_buffer_pool_push(handle->data_path_msg_pool, msg);
}

struct vysmaw_message *
spectra_message_new(
  vysmaw_handle handle, struct rdma_cm_id *id,
  GHashTable *mrs, const struct vysmaw_data_info *info,
  unsigned num_spectra, pool_id_t *pool_id,
  struct vys_error_record **error_record)
{
  size_t buff_size = spectrum_buffer_size(info);
  struct vysmaw_message *result = message_new(handle, VYSMAW_MESSAGE_SPECTRA);
  result->content.spectra.info = *info;
  result->content.spectra.spectrum_buffer_size = buff_size;
  result->content.spectra.num_spectra = num_spectra;
  result->content.spectra.header_buffer = NULL;
  result->content.spectra.data_buffer = handle->new_valid_buffer_fn(
    handle, id, mrs, num_spectra * buff_size, pool_id, error_record);
  if (G_LIKELY(result->content.spectra.data_buffer != NULL)) {
    result->content.spectra.header_buffer =
      vys_buffer_pool_pop(handle->header_pool);
    if (G_LIKELY(result->content.spectra.header_buffer != NULL)) {
      // note that we don't initialize the result->content.data array
      if (G_UNLIKELY(handle->num_spectrum_buffers_unavailable > 0))
        post_spectrum_buffer_starvation(handle);
      if (G_UNLIKELY(handle->num_spectra_mismatched_version > 0))
        post_version_mismatch(handle);
    } else {
      mark_spectrum_buffer_starvation(handle); 
      vysmaw_message_unref(result);
      result = NULL;
    }
  } else {
    mark_spectrum_buffer_starvation(handle); 
    vysmaw_message_unref(result);
    result = NULL;
  }
  return result;
}

void
mark_spectrum_buffer_starvation(vysmaw_handle handle)
{
  handle->num_spectrum_buffers_unavailable++;
  if (handle->num_spectrum_buffers_unavailable
      >= handle->config.max_starvation_latency)
    post_spectrum_buffer_starvation(handle);
}

void
mark_signal_receive_failure(vysmaw_handle handle, enum ibv_wc_status status)
{
  post_signal_receive_failure(handle, status);
}

void
mark_version_mismatch(vysmaw_handle handle, unsigned received_message_version)
{
  if (received_message_version != handle->mismatched_version
      && handle->num_spectra_mismatched_version > 0)
    post_version_mismatch(handle);
  handle->num_spectra_mismatched_version++;
  if (handle->num_spectra_mismatched_version
      >= handle->config.max_version_mismatch_latency)
    post_version_mismatch(handle);
}

void
mark_signal_receive_queue_underflow(vysmaw_handle handle)
{
  post_signal_receive_queue_underflow(handle);
}

void
message_release_all_buffers(struct vysmaw_message *message)
{
  if (message->typ == VYSMAW_MESSAGE_SPECTRA) {
    struct spectrum_buffer_pool *pool =
      message->handle->lookup_buffer_pool_fn(message);
    if (G_LIKELY(pool != NULL)) {
      if (G_LIKELY(message->content.spectra.data_buffer != NULL))
        spectrum_buffer_pool_push(pool, message->content.spectra.data_buffer);
      if (G_LIKELY(message->content.spectra.header_buffer != NULL))
        vys_buffer_pool_push(
          message->handle->header_pool,
          message->content.spectra.header_buffer);
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
  message_release_all_buffers(message);
  vysmaw_message_free_syserr_desc(message);
  handle_unref(message->handle);
}

int
dereg_mr(struct ibv_mr *mr, struct vys_error_record **error_record)
{
  int rc = ibv_dereg_mr(mr);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(error_record, errno, "ibv_dereg_mr");
  return rc;
}

int
register_one_spectrum_buffer_pool(
  struct spectrum_buffer_pool *sb_pool, struct rdma_cm_id *id,
  GHashTable *mrs, struct vys_error_record **error_record)
{
  int result;
  struct ibv_mr *mr =
    ibv_reg_mr(
      id->pd,
      sb_pool->pool->pool,
      sb_pool->pool->pool_size,
      IBV_ACCESS_LOCAL_WRITE);
  if (G_LIKELY(mr != NULL)) {
    g_hash_table_insert(mrs, spectrum_buffer_pool_ref(sb_pool), mr);
    result = 0;
  } else {
    VERB_ERR(error_record, errno, "ibv_reg_mr");
    result = -1;
  }
  return result;
}

int
deregister_one_spectrum_buffer_pool(
  struct spectrum_buffer_pool *sb_pool, GHashTable *mrs,
  struct vys_error_record **error_record)
{
  int rc = 0;
  struct ibv_mr *mr = g_hash_table_lookup(mrs, sb_pool);
  if (G_LIKELY(mr != NULL))
    rc = dereg_mr(mr, error_record);
  g_hash_table_remove(mrs, sb_pool);
  return rc;
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
convert_valid_to_id_failure(
  struct vysmaw_message *message, unsigned buffer_index)
{
  g_assert(message->typ == VYSMAW_MESSAGE_SPECTRA);
  message->data[buffer_index].failed_verification = true;
  message->data[buffer_index].values = NULL;
}

void
convert_valid_to_rdma_read_failure(
  struct vysmaw_message *message, unsigned buffer_index,
  enum ibv_wc_status status)
{
  g_assert(message->typ == VYSMAW_MESSAGE_SPECTRA);
  g_strlcpy(message->data[buffer_index].rdma_read_status,
            ibv_wc_status_str(status),
            sizeof(message->data[buffer_index].rdma_read_status));
  message->data[buffer_index].values = NULL;
}

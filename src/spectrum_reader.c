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
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <spectrum_reader.h>

#define CM_EVENT_FD_INDEX 0
#define INACTIVITY_TIMER_FD_INDEX 1
#define READ_REQUEST_QUEUE_FD_INDEX 2
#define BUFFER_POOL_IDLE_TIMER_FD_INDEX 3
#define NUM_FIXED_FDS 4

enum run_state {
  STATE_INIT,
  STATE_RUN,
  STATE_QUIT,
  STATE_DONE
};

struct spectrum_reader_context_ {
  struct spectrum_reader_context *shared;
  enum run_state state;
  struct data_path_message *quit_msg;
  struct data_path_message *end_msg;
  GArray *restrict pollfds;
  GArray *restrict new_pollfds;
  struct rdma_event_channel *event_channel;
  struct ibv_mr *header_pool_mr;
  GHashTable *mrs;
  GHashTable *connections;
  GSequence *fd_connections;
  GSList *free_rdma_req_blocks;
  long num_free_rdma_req_blocks;
  unsigned rdma_req_backlog;
};

struct server_connection_context {
  struct rdma_cm_id *id;
  struct ibv_wc *wcs;
  struct sockaddr_in *addr;
  uint32_t *rkeys;
  bool established;
  bool disconnecting;
  unsigned max_posted_wr;
  unsigned num_posted_wr;
  GQueue *reqs;
  struct vysmaw_message *prev_message;
  pool_id_t prev_pool;

  unsigned num_not_ack;
  unsigned min_ack;

  GTimer *last_access;
};

enum rdma_req_result {
  RDMA_REQ_SUCCESS, RDMA_REQ_READ_FAILURE,
  RDMA_REQ_ID_VERIFICATION_FAILURE
};

struct rdma_req {
  unsigned index;
  struct vys_spectrum_info spectrum_info;
  enum rdma_req_result result;
  enum ibv_wc_status status;
};

struct rdma_req_block {
  struct vysmaw_data_info data_info;
  uint8_t mr_id;
  vysmaw_handle handle;
  unsigned next_req;
  unsigned num_req;
  unsigned num_req_pending;
  struct vysmaw_message *message;
  struct rdma_req reqs[];
};

#define SIZEOF_RDMA_REQ_BLOCK(n) (\
    sizeof(struct rdma_req_block) + (n) * sizeof(struct rdma_req))
#define RDMA_REQ_BLOCK_P(req_p) (                               \
    (struct rdma_req_block*)(                                   \
      (void*)(req_p) - (req_p)->index * sizeof(struct rdma_req) \
      - offsetof(struct rdma_req_block, reqs)))

static struct rdma_req_block *new_rdma_req_block(
  struct spectrum_reader_context_ *context,
  const struct server_connection_context *conn_ctx,
  const struct vys_signal_msg_payload *payload)
  __attribute__((nonnull,malloc));
static void free_rdma_req_block(
  struct spectrum_reader_context_ *context, struct rdma_req_block *block)
  __attribute__((nonnull));
static void cancel_rdma_req(
  struct spectrum_reader_context_ *context, struct rdma_req *req)
  __attribute__((nonnull));
static void fulfill_rdma_req(
  struct spectrum_reader_context_ *context, struct rdma_req *req)
  __attribute__((nonnull));
static int compare_server_comp_ch_fd(
  const struct server_connection_context *c1,
  const struct server_connection_context *c2,
  void *unused __attribute__((unused)))
  __attribute__((nonnull,pure));
static int start_rdma_cm(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int stop_rdma_cm(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static void set_max_posted_wr(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx, unsigned max_posted_wr)
  __attribute__((nonnull));
static struct server_connection_context *initiate_server_connection(
  struct spectrum_reader_context_ *context,
  const struct sockaddr_in *sockaddr, struct vys_error_record **error_record)
  __attribute__((nonnull,returns_nonnull,malloc));
static int find_connection(
  struct spectrum_reader_context_ *context, struct sockaddr_in *sockaddr,
  struct server_connection_context **conn_ctx, GQueue **req_queue,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_signal_message(
  struct spectrum_reader_context_ *context, struct vys_signal_msg *msg,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_data_path_message(
  struct spectrum_reader_context_ *context, struct data_path_message *msg,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_server_addr_resolved(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_server_route_resolved(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int post_server_reads(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_server_established(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  uint32_t *rkeys, unsigned initiator_depth,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static GSequenceIter *find_server_connection_context_iter(
  const struct spectrum_reader_context_ *context, int fd)
  __attribute__((nonnull,returns_nonnull));
static struct server_connection_context *find_server_connection_context(
  const struct spectrum_reader_context_ *context, int fd)
  __attribute__((nonnull));
static int begin_server_disconnect(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int complete_server_disconnect(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_cm_event(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int poll_completions(
  struct spectrum_reader_context_ *context,
  struct server_connection_context *conn_ctx, GSList **reqs,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static void ack_completions(
  struct server_connection_context *conn_ctx, unsigned min_ack)
  __attribute__((nonnull));
static int get_completed_requests(
  struct spectrum_reader_context_ *context, int fd,
  struct server_connection_context **conn_ctx, GSList **reqs,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_read_completion(
  struct spectrum_reader_context_ *context, unsigned pfd,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_inactivity_timer_event(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_buffer_pool_idle_timer_event(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_poll_events(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int to_quit_state(
  struct spectrum_reader_context_ *context,
  struct data_path_message *msg, struct vys_error_record **error_record)
  __attribute__((nonnull(1,3)));
static int spectrum_reader_loop(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int start_inactivity_timer(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int stop_inactivity_timer(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int start_buffer_pool_idle_timer(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int stop_buffer_pool_idle_timer(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int start_read_request_poll(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int stop_read_request_poll(
  struct spectrum_reader_context_ *context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int loopback_msg(
  struct spectrum_reader_context_ *context,
  struct data_path_message *msg, struct vys_error_record **error_record)
  __attribute__((nonnull));

static struct rdma_req_block *
new_rdma_req_block(
  struct spectrum_reader_context_ *context,
  const struct server_connection_context *conn_ctx,
  const struct vys_signal_msg_payload *payload)
{
  struct rdma_req_block *result;
  if (context->free_rdma_req_blocks == NULL) {
    result = g_slice_alloc(
      SIZEOF_RDMA_REQ_BLOCK(context->shared->handle->signal_msg_num_spectra));
    ++(context->num_free_rdma_req_blocks);
  } else {
    result = context->free_rdma_req_blocks->data;
    context->free_rdma_req_blocks =
      g_slist_delete_link(
        context->free_rdma_req_blocks,
        context->free_rdma_req_blocks);
  }

  result->data_info.num_channels = payload->num_channels;
  result->data_info.num_bins = payload->num_bins;
  result->data_info.bin_stride = payload->bin_stride;
  result->data_info.stations[0] = payload->stations[0];
  result->data_info.stations[1] = payload->stations[1];
  result->data_info.baseband_index = payload->baseband_index;
  result->data_info.baseband_id = payload->baseband_id;
  result->data_info.spectral_window_index = payload->spectral_window_index;
  result->data_info.polarization_product_id = payload->polarization_product_id;
  result->data_info.timestamp = payload->infos->timestamp;
  memcpy(result->data_info.config_id, payload->config_id,
         sizeof(result->data_info.config_id));

  result->handle = context->shared->handle;
  result->message = NULL;
  result->mr_id = payload->mr_id;

  unsigned num_req = 0;
  const struct vys_spectrum_info *info = payload->infos;
  struct rdma_req *req = result->reqs;
  for (unsigned i = 0; i < payload->num_spectra; ++i, ++info) {
    if (info->data_addr != 0) {
      memcpy(&(req->spectrum_info), info, sizeof(req->spectrum_info));
      req->index = num_req++;
      ++req;
    }
  }
  if (G_LIKELY(num_req > 0)) {
    result->next_req = 0;
    result->num_req = num_req;
    result->num_req_pending = num_req;
  } else {
    free_rdma_req_block(context, result);
    result = NULL;
  }
  return result;
}

static void
free_rdma_req_block(
  struct spectrum_reader_context_ *context, struct rdma_req_block *block)
{
  context->free_rdma_req_blocks =
    g_slist_prepend(context->free_rdma_req_blocks, block);
}

static void
cancel_rdma_req(struct spectrum_reader_context_ *context, struct rdma_req *req)
{
  struct rdma_req_block *blk = RDMA_REQ_BLOCK_P(req);
  if (blk->message != NULL) {
    blk->message->data[req->index].values = NULL;
    blk->message->data[req->index].failed_verification = false;
    blk->message->data[req->index].rdma_read_status[0] = '\0';
    blk->message->data[req->index].values = NULL;
  }
  fulfill_rdma_req(context, req);
}

static void
fulfill_rdma_req(struct spectrum_reader_context_ *context, struct rdma_req *req)
{
  struct rdma_req_block *blk = RDMA_REQ_BLOCK_P(req);
  if (--(blk->num_req_pending) == 0) {
    if (G_LIKELY(blk->message != NULL))
      post_msg(blk->handle, blk->message);
    free_rdma_req_block(context, blk);
  }
}

static int
compare_server_comp_ch_fd(const struct server_connection_context *c1,
                          const struct server_connection_context *c2,
                          void *unused)
{
  return c1->id->send_cq_channel->fd - c2->id->send_cq_channel->fd;
}

static int
start_rdma_cm(struct spectrum_reader_context_ *context,
              struct vys_error_record **error_record)
{
  /* rdma cm event channel */
  context->event_channel = rdma_create_event_channel();
  if (G_UNLIKELY(context->event_channel == NULL)) {
    VERB_ERR(error_record, errno, "rdma_create_event_channel");
    return -1;
  }
  int rc = set_nonblocking(context->event_channel->fd);
  if (G_UNLIKELY(rc != 0)) {
    MSG_ERROR(error_record, errno,
              "failed to set rdma cm event channel to non-blocking: %s",
              strerror(errno));
    return rc;
  }
  struct pollfd *pfd =
    &g_array_index(context->pollfds, struct pollfd, CM_EVENT_FD_INDEX);
  pfd->fd = context->event_channel->fd;
  pfd->events = POLLIN;

  context->connections = g_hash_table_new_full(
    (GHashFunc)sockaddr_hash, (GEqualFunc)sockaddr_equal,
    (GDestroyNotify)free_sockaddr_key, NULL);
  context->fd_connections = g_sequence_new(NULL);

  return rc;
}

static int
stop_rdma_cm(struct spectrum_reader_context_ *context,
             struct vys_error_record **error_record)
{
  if (context->fd_connections != NULL)
    g_sequence_free(context->fd_connections);

  if (context->connections != NULL)
    g_hash_table_destroy(context->connections);

  if (context->event_channel != NULL)
    rdma_destroy_event_channel(context->event_channel);

  return 0;
}

static void
set_max_posted_wr(struct spectrum_reader_context_ *context,
                  struct server_connection_context *conn_ctx,
                  unsigned max_posted_wr)
{
  conn_ctx->max_posted_wr = max_posted_wr;
  conn_ctx->min_ack =
    MAX(context->shared->handle->config.rdma_read_min_ack, 1);
}

static struct server_connection_context *
initiate_server_connection(struct spectrum_reader_context_ *context,
                           const struct sockaddr_in *sockaddr,
                           struct vys_error_record **error_record)
{
  struct rdma_cm_id *id;
  int rc = rdma_create_id(context->event_channel, &id, NULL, RDMA_PS_TCP);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_create_id");
    return NULL;
  }

  struct sockaddr_in *key = new_sockaddr_key(sockaddr);
  rc = rdma_resolve_addr(
    id, NULL, (struct sockaddr *)key,
    context->shared->handle->config.resolve_addr_timeout_ms);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_resolve_addr");
    rdma_destroy_id(id);
    free_sockaddr_key(key);
    return NULL;
  }

  struct server_connection_context *result =
    g_slice_new0(struct server_connection_context);
  result->id = id;
  result->addr = key;
  result->reqs = g_queue_new();
  set_max_posted_wr(context, result,
                    context->shared->handle->config.rdma_read_max_posted);
  /* set wcs field later, after final value of max_posted_wr has been
   * computed */
  result->last_access = g_timer_new();
  g_hash_table_insert(context->connections, key, result);
  return result;
}

static int
find_connection(struct spectrum_reader_context_ *context,
                struct sockaddr_in *sockaddr,
                struct server_connection_context **conn_ctx,
                GQueue **req_queue, struct vys_error_record **error_record)
{
  *conn_ctx = g_hash_table_lookup(context->connections, sockaddr);
  if (*conn_ctx == NULL) {
    *conn_ctx = initiate_server_connection(context, sockaddr, error_record);
    if (G_UNLIKELY(*conn_ctx == NULL))
      return -1;
  }
  if (!(*conn_ctx)->disconnecting
      && ((*conn_ctx)->established
          || context->shared->handle->config.preconnect_backlog))
    *req_queue = (*conn_ctx)->reqs;
  else
    *req_queue = NULL;
  return 0;
}

static int
on_signal_message(struct spectrum_reader_context_ *context,
                  struct vys_signal_msg *msg,
                  struct vys_error_record **error_record)
{
  struct vys_signal_msg_payload *payload = &(msg->payload);
  GQueue *reqs = NULL;
  struct server_connection_context *conn_ctx = NULL;

  int rc = find_connection(context, &payload->sockaddr, &conn_ctx, &reqs,
                           error_record);

  if (G_LIKELY(rc == 0 && reqs != NULL && context->state < STATE_QUIT)) {
    struct rdma_req_block *blk =
      new_rdma_req_block(context, conn_ctx, payload);
    if (G_LIKELY(blk != NULL)) {
      context->rdma_req_backlog += blk->num_req;
      g_queue_push_tail(reqs, blk);
      if (conn_ctx->established)
        rc = post_server_reads(context, conn_ctx, error_record);
    }
  }

  return rc;
}

static int
on_data_path_message(struct spectrum_reader_context_ *context,
                     struct data_path_message *msg,
                     struct vys_error_record **error_record)
{
  vysmaw_handle handle = context->shared->handle;
  int rc = 0;
  switch (msg->typ) {
  case DATA_PATH_SIGNAL_MSG:
    if (G_LIKELY(context->state == STATE_RUN))
      rc = on_signal_message(context, &msg->signal_msg, error_record);
    data_path_message_free(handle, msg);
    break;

  case DATA_PATH_RECEIVE_FAIL:
    mark_signal_receive_failure(handle, msg->wc_status);
    data_path_message_free(handle, msg);
    break;

  case DATA_PATH_VERSION_MISMATCH:
    mark_version_mismatch(handle, msg->received_message_version);
    data_path_message_free(handle, msg);
    break;

  case DATA_PATH_RECEIVE_UNDERFLOW:
    mark_signal_receive_queue_underflow(handle);
    data_path_message_free(handle, msg);
    break;

  case DATA_PATH_QUIT:
    if (context->quit_msg == NULL) {
      rc = to_quit_state(context, msg, error_record);
    } else {
      if (context->quit_msg == msg) {
        if (handle->num_spectrum_buffers_unavailable > 0)
          post_spectrum_buffer_starvation(handle);
        if (handle->num_spectra_mismatched_version > 0)
          post_version_mismatch(handle);
        context->end_msg = data_path_message_new(handle);
        context->end_msg->typ = DATA_PATH_END;
        context->end_msg->error_record = NULL;
        rc = loopback_msg(context, context->end_msg, error_record);
        context->quit_msg = NULL;
      }
      data_path_message_free(handle, msg);
    }
    break;

  case DATA_PATH_END:
    context->state = STATE_DONE;
    stop_read_request_poll(context, error_record);
    break;

  default:
    g_assert_not_reached();
    break;
  }
  return rc;
}

static int
on_server_addr_resolved(struct spectrum_reader_context_ *context,
                        struct server_connection_context *conn_ctx,
                        struct vys_error_record **error_record)
{
  /* query ib device */
  struct ibv_device_attr dev_attr;
  int rc = ibv_query_device(conn_ctx->id->verbs, &dev_attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_query_device");
    return -1;
  }
  set_max_posted_wr(
    context, conn_ctx,
    MIN(conn_ctx->max_posted_wr, dev_attr.max_qp_init_rd_atom));

  /* create qp */
  struct ibv_qp_init_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.qp_type = IBV_QPT_RC;
  attr.sq_sig_all = 1;
  attr.cap.max_send_wr = conn_ctx->max_posted_wr;
  attr.cap.max_recv_wr = 1;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  rc = rdma_create_qp(conn_ctx->id, NULL, &attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_create_qp");
    conn_ctx->id->qp = NULL;
    return -1;
  }

  /* record maximum number of work requests we can post at one time */
  set_max_posted_wr(context, conn_ctx,
                    MIN(conn_ctx->max_posted_wr, attr.cap.max_send_wr));

  /* resize cq for the maximum number of posted work requests */
  rc = ibv_resize_cq(conn_ctx->id->send_cq, conn_ctx->max_posted_wr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "ibv_resize_cq");
    return -1;
  }

  /* now may insert the connection into the list sorted by completion fd */
  g_sequence_insert_sorted(
    context->fd_connections, conn_ctx,
    (GCompareDataFunc)compare_server_comp_ch_fd, NULL);

  rc = rdma_resolve_route(
    conn_ctx->id,
    context->shared->handle->config.resolve_route_timeout_ms);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(error_record, errno, "rdma_resolve_route");

  return rc;
}

static int
on_server_route_resolved(struct spectrum_reader_context_ *context,
                         struct server_connection_context *conn_ctx,
                         struct vys_error_record **error_record)
{
  /* set up send completion queue event channel */
  int fd = conn_ctx->id->send_cq_channel->fd;
  set_nonblocking(fd);
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN
  };
  if (context->new_pollfds->len == 0)
    g_array_append_vals(context->new_pollfds, context->pollfds->data,
                        context->pollfds->len);
  g_array_append_val(context->new_pollfds, pfd);

  /* post first request for notification from completion queue */
  int rc = ibv_req_notify_cq(conn_ctx->id->send_cq, 0);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_req_notify_cq");
    return rc;
  }

  /* connect to server */
  struct rdma_conn_param conn_param;
  memset(&conn_param, 0, sizeof(conn_param));
  conn_param.initiator_depth = conn_ctx->max_posted_wr;
  rc = rdma_connect(conn_ctx->id, &conn_param);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(error_record, errno, "rdma_connect");
  return rc;
}

static int
post_server_reads(struct spectrum_reader_context_ *context,
                  struct server_connection_context *conn_ctx,
                  struct vys_error_record **error_record)
{
  if (G_UNLIKELY(context->header_pool_mr == NULL)) {
    context->header_pool_mr =
      ibv_reg_mr(
        conn_ctx->id->pd,
        context->shared->handle->header_pool->pool,
        context->shared->handle->header_pool->pool_size,
        IBV_ACCESS_LOCAL_WRITE);
    if (G_UNLIKELY(context->header_pool_mr == NULL)) {
      VERB_ERR(error_record, errno, "ibv_reg_mr");
      return -1;
    }
  }

  int rc = 0;
  bool canceled = false;
  struct ibv_mr *mr = NULL;
  pool_id_t pool_id = NULL;
  while (rc == 0
         && !g_queue_is_empty(conn_ctx->reqs)
         && conn_ctx->num_posted_wr < conn_ctx->max_posted_wr
         && !canceled) {
    struct rdma_req_block *rblk = g_queue_peek_head(conn_ctx->reqs);
    struct rdma_req *req = &rblk->reqs[rblk->next_req];
    if (rblk->next_req == rblk->num_req - 1)
      g_queue_pop_head(conn_ctx->reqs);
    else
      ++(rblk->next_req);
    --(context->rdma_req_backlog);
    if (rblk->message == NULL) {
      rblk->message =
        spectra_message_new(
          context->shared->handle, conn_ctx->id, context->mrs,
          &rblk->data_info, rblk->num_req, &conn_ctx->prev_pool, error_record);
      if (G_LIKELY(rblk->message != NULL)) {
        // zero out values for previously canceled requests arising from failure
        // to allocate rblk->message
        for (unsigned i = 0; i < req->index; ++i) {
          rblk->message->data[i].failed_verification = false;
          rblk->message->data[i].rdma_read_status[0] = '\0';
          rblk->message->data[i].header = NULL;
          rblk->message->data[i].values = NULL;
        }
      } else {
        cancel_rdma_req(context, req);
        canceled = true;
      }
    }
    if (G_LIKELY(!canceled)) {
      if (G_UNLIKELY((mr == NULL || conn_ctx->prev_pool != pool_id))) {
        pool_id = conn_ctx->prev_pool;
        mr = g_hash_table_lookup(context->mrs, pool_id);
        if (G_UNLIKELY(mr == NULL)) {
          struct spectrum_buffer_pool *sb_pool = get_buffer_pool(rblk->message);
          if (G_LIKELY(sb_pool != NULL)) {
            rc = register_one_spectrum_buffer_pool(
              sb_pool, conn_ctx->id, context->mrs, error_record);
            mr = g_hash_table_lookup(context->mrs, pool_id);
            g_assert(mr != NULL);
          } else {
            rc = ENOMEM;
            MSG_ERROR(
              error_record,
              ENOMEM,
              "%s",
              "failed to get buffer pool memory");
          }
        }
      }
      if (G_LIKELY(rc == 0)) {
        struct vysmaw_spectrum *vs = &rblk->message->data[req->index];
        vs->timestamp = req->spectrum_info.timestamp;
        vs->failed_verification = false;
        vs->rdma_read_status[0] = '\0';
        vs->values =
          rblk->message->content.spectra.data_buffer
          + req->index * rblk->message->content.spectra.spectrum_buffer_size;
        vs->header =
          rblk->message->content.spectra.header_buffer
          + req->index * sizeof(union vysmaw_spectrum_header);
        struct ibv_sge sge[2] = {
          {(uint64_t)(vs->header),
           sizeof(union vysmaw_spectrum_header),
           context->header_pool_mr->lkey},
          {(uint64_t)(vs->values),
           rblk->message->content.spectra.spectrum_buffer_size,
           mr->lkey}
        };
        rc = rdma_post_readv(
          conn_ctx->id, req, sge, sizeof(sge) / sizeof(sge[0]), 0, 
          req->spectrum_info.data_addr, conn_ctx->rkeys[rblk->mr_id]);
        if (G_UNLIKELY(rc != 0))
          VERB_ERR(error_record, errno, "rdma_post_readv");
      }
      if (G_LIKELY(rc == 0)) {
        ++(conn_ctx->num_posted_wr);
      } else {
        cancel_rdma_req(context, req);
        canceled = true;
      }
    }
  }
  return rc;
}

static int
on_server_established(struct spectrum_reader_context_ *context,
                      struct server_connection_context *conn_ctx,
                      uint32_t *rkeys, unsigned initiator_depth,
                      struct vys_error_record **error_record)
{
  conn_ctx->rkeys = rkeys;
  set_max_posted_wr(context, conn_ctx,
                    MIN(conn_ctx->max_posted_wr, initiator_depth));
  conn_ctx->wcs = g_new(struct ibv_wc, conn_ctx->max_posted_wr);
  conn_ctx->established = true;
  return post_server_reads(context, conn_ctx, error_record);
}

static GSequenceIter *
find_server_connection_context_iter(
  const struct spectrum_reader_context_ *context, int fd)
{
  struct ibv_comp_channel fd_ch = {
    .fd = fd
  };
  struct rdma_cm_id fd_id = {
    .send_cq_channel = &fd_ch
  };
  struct server_connection_context fd_ctx = {
    .id = &fd_id
  };
  GSequenceIter *iter =
    g_sequence_search(
      context->fd_connections, &fd_ctx,
      (GCompareDataFunc)compare_server_comp_ch_fd, NULL);
  if (!g_sequence_iter_is_begin(iter))
    iter = g_sequence_iter_prev(iter);
  return iter;
}

static struct server_connection_context *
find_server_connection_context(const struct spectrum_reader_context_ *context,
                               int fd)
{
  GSequenceIter *iter = find_server_connection_context_iter(context, fd);
  if (g_sequence_iter_is_end(iter))
    return NULL;
  return g_sequence_get(iter);
}

static int
begin_server_disconnect(struct spectrum_reader_context_ *context,
                        struct server_connection_context *conn_ctx,
                        struct vys_error_record **error_record)
{
  int rc = 0;
  if (!conn_ctx->disconnecting) {
    while (!g_queue_is_empty(conn_ctx->reqs)) {
      struct rdma_req_block *rblk = g_queue_pop_head(conn_ctx->reqs);
      context->rdma_req_backlog -= rblk->num_req - rblk->next_req;
      if (rblk->message != NULL) {
        for (unsigned i = rblk->next_req; i < rblk->num_req; ++i)
          cancel_rdma_req(context, &rblk->reqs[i]);
      } else {
        free_rdma_req_block(context, rblk);
      }
    }

    conn_ctx->disconnecting = true;
    if (conn_ctx->established) {
      conn_ctx->established = false;
      rc = rdma_disconnect(conn_ctx->id);
      if (G_UNLIKELY(rc != 0))
        VERB_ERR(error_record, errno, "rdma_disconnect");
    } else {
      rc = complete_server_disconnect(context, conn_ctx, error_record);
    }
  }
  return rc;
}

static int
complete_server_disconnect(struct spectrum_reader_context_ *context,
                           struct server_connection_context *conn_ctx,
                           struct vys_error_record **error_record)
{
  if (conn_ctx->reqs != NULL)
    g_queue_free(conn_ctx->reqs);

  if (conn_ctx->rkeys != NULL)
    g_free(conn_ctx->rkeys);

  struct vys_error_record *er = NULL;
  bool removed = g_hash_table_remove(context->connections, conn_ctx->addr);
  if (G_UNLIKELY(!removed))
    MSG_ERROR(&er, -1, "%s",
              "failed to remove server connection record from client");

  assert(conn_ctx->id != NULL);
  if (conn_ctx->id->send_cq_channel != NULL) {
    GSequenceIter *conn =
      find_server_connection_context_iter(
        context, conn_ctx->id->send_cq_channel->fd);
    if (conn != NULL)
      g_sequence_remove(conn);
  }

  if (context->new_pollfds->len == 0)
    g_array_append_vals(context->new_pollfds, context->pollfds->data,
                        context->pollfds->len);

  if (conn_ctx->id->send_cq_channel != NULL)
    for (unsigned i = 0; i < context->new_pollfds->len; ++i) {
      struct pollfd *pfd =
        &(g_array_index(context->new_pollfds, struct pollfd, i));
      if (pfd->fd == conn_ctx->id->send_cq_channel->fd) {
        g_array_remove_index(context->new_pollfds, i);
        break;
      }
    }

  ack_completions(conn_ctx, 1);
  if (conn_ctx->id->qp != NULL)
    rdma_destroy_qp(conn_ctx->id);

  // deregister memory regions when there are no more connections
  if (g_hash_table_size(context->connections) == 0) {
    if (context->mrs != NULL) {
      gboolean dereg(gpointer unused, struct ibv_mr *mr,
                     struct vys_error_record **errs) {
        dereg_mr(mr, errs);
        return TRUE;
      }
      g_hash_table_foreach_remove(context->mrs, (GHRFunc)dereg, &er);
    }
    if (context->header_pool_mr != NULL) {
      dereg_mr(context->header_pool_mr, &er);
      context->header_pool_mr = NULL;
    }
  }

  int rc = rdma_destroy_id(conn_ctx->id);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(&er, errno, "rdma_destroy_id");

  if (conn_ctx->wcs != NULL)
    g_free(conn_ctx->wcs);

  if (conn_ctx->last_access != NULL)
    g_timer_destroy(conn_ctx->last_access);

  g_slice_free(struct server_connection_context, conn_ctx);

  *error_record = vys_error_record_concat(er, *error_record);
  return ((er != NULL) ? -1 : 0);
}

static int
on_cm_event(struct spectrum_reader_context_ *context,
            struct vys_error_record **error_record)
{
  /* get event */
  struct rdma_cm_event *event = NULL;
  int rc = rdma_get_cm_event(context->event_channel, &event);
  if (G_UNLIKELY(rc != 0)) {
    if (G_UNLIKELY(errno == EAGAIN || errno == EWOULDBLOCK))
      return 0;
    VERB_ERR(error_record, errno, "rdma_get_cm_event");
    return rc;
  }

  /* look up server connection */
  struct server_connection_context *conn_ctx =
    g_hash_table_lookup(context->connections,
                        &event->id->route.addr.dst_sin);
  if (G_UNLIKELY(conn_ctx == NULL)) {
    /* MSG_ERROR( */
    /*   error_record, -1, */
    /*   "failed to find connection for event %s", */
    /*   rdma_event_str(event->event)); */
    return 0;
  }

  /* Optimistically read some values from the event, even if they might only
   * be valid for some event types. */
  enum rdma_cm_event_type ev_type = event->event;
  void *private_data;
  if (event->param.conn.private_data > 0) {
    private_data = g_malloc(event->param.conn.private_data_len);
    memcpy(private_data, event->param.conn.private_data,
           event->param.conn.private_data_len);
  } else {
    private_data = NULL;
  }
  unsigned initiator_depth = event->param.conn.initiator_depth;

  /* ack event */
  rc = rdma_ack_cm_event(event);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_ack_cm_event");
    return rc;
  }

  /* dispatch event based on type */
  switch (ev_type) {
  case RDMA_CM_EVENT_ADDR_RESOLVED:
    if (G_UNLIKELY(context->state >= STATE_QUIT)) {
      rc = begin_server_disconnect(context, conn_ctx, error_record);
    } else {
      rc = on_server_addr_resolved(context, conn_ctx, error_record);
      if (rc != 0)
        begin_server_disconnect(context, conn_ctx, error_record);
    }
    break;

  case RDMA_CM_EVENT_ROUTE_RESOLVED:
    if (G_UNLIKELY(context->state >= STATE_QUIT)) {
      rc = begin_server_disconnect(context, conn_ctx, error_record);
    } else {
      rc = on_server_route_resolved(context, conn_ctx, error_record);
      if (rc != 0)
        begin_server_disconnect(context, conn_ctx, error_record);
    }
    break;

  case RDMA_CM_EVENT_ESTABLISHED:
    if (G_UNLIKELY(context->state >= STATE_QUIT)) {
      rc = begin_server_disconnect(context, conn_ctx, error_record);
    } else {
      rc = on_server_established(context, conn_ctx, private_data,
                                 initiator_depth, error_record);
      private_data = NULL;
      if (rc != 0)
        begin_server_disconnect(context, conn_ctx, error_record);
    }
    break;

  case RDMA_CM_EVENT_DISCONNECTED:
    rc = begin_server_disconnect(context, conn_ctx, error_record);
    if (rc == 0 && conn_ctx->num_posted_wr == 0)
      rc = complete_server_disconnect(context, conn_ctx, error_record);
    break;

  case RDMA_CM_EVENT_ADDR_ERROR:
  case RDMA_CM_EVENT_ROUTE_ERROR:
  case RDMA_CM_EVENT_CONNECT_ERROR:
  case RDMA_CM_EVENT_UNREACHABLE:
  case RDMA_CM_EVENT_REJECTED: {
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(conn_ctx->id->route.addr.dst_sin),
              addr, sizeof(addr));
    MSG_ERROR(error_record, -1, "%s on %s", rdma_event_str(ev_type), addr);
    rc = -1;
    break;
  }
  default:
    break;
  }

  if (G_UNLIKELY(private_data != NULL))
    g_free(private_data);

  return rc;
}

static int
poll_completions(struct spectrum_reader_context_ *context,
                 struct server_connection_context *conn_ctx, GSList **reqs,
                 struct vys_error_record **error_record)
{
  *reqs = NULL;
  int nc = ibv_poll_cq(conn_ctx->id->send_cq, conn_ctx->max_posted_wr,
                       conn_ctx->wcs);
  if (G_UNLIKELY(nc < 0)) {
    VERB_ERR(error_record, errno, "ibv_poll_cq");
    return errno;
  }
  if (G_LIKELY(nc > 0)) {
    g_assert(conn_ctx->num_posted_wr >= nc);
    conn_ctx->num_posted_wr -= nc;
    //__atomic_thread_fence(__ATOMIC_RELEASE);
    for (unsigned i = 0; i < nc; ++i) {
      struct rdma_req *req = (struct rdma_req *)conn_ctx->wcs[i].wr_id;
      req->status = conn_ctx->wcs[i].status;
      if (G_LIKELY(req->status == IBV_WC_SUCCESS)) {
        struct rdma_req_block *rblk = RDMA_REQ_BLOCK_P(req);
        if (rblk->message->data[req->index].header->id_num
            == req->spectrum_info.id_num)
          req->result = RDMA_REQ_SUCCESS;
        else
          req->result = RDMA_REQ_ID_VERIFICATION_FAILURE;
      } else {
        req->result = RDMA_REQ_READ_FAILURE;
        struct ibv_qp_attr attr;
        struct ibv_qp_init_attr init_attr;
        int rc =
          ibv_query_qp(conn_ctx->id->qp, &attr, IBV_QP_STATE, &init_attr);
        if (G_UNLIKELY(rc != 0)) {
          VERB_ERR(error_record, errno, "ibv_query_qp");
          return errno;
        }
        /* Upon some failures the QP transitions to the error state, which then
         * leads to errors on all subsequent work requests. Disconnecting should
         * allow a new connection later. */
        if (attr.qp_state == IBV_QPS_ERR)
          begin_server_disconnect(context, conn_ctx, error_record);
      }
      *reqs = g_slist_prepend(*reqs, req);
    }
  }
  return 0;
}

static void
ack_completions(struct server_connection_context *conn_ctx, unsigned min_ack)
{
  if (conn_ctx->num_not_ack >= min_ack) {
    if (conn_ctx->id != NULL)
      ibv_ack_cq_events(conn_ctx->id->send_cq, conn_ctx->num_not_ack);
    conn_ctx->num_not_ack = 0;
  }
}

static int
get_completed_requests(struct spectrum_reader_context_ *context, int fd,
                       struct server_connection_context **conn_ctx,
                       GSList **reqs, struct vys_error_record **error_record)
{
  /* look up server_connection_context instance for given fd */
  *conn_ctx = find_server_connection_context(context, fd);
  if (G_UNLIKELY(*conn_ctx == NULL)) {
    MSG_ERROR(error_record, -1,
              "failed to find server context for read completion on %d",
              fd);
    return -1;
  }

  struct ibv_cq *ev_cq;
  void *cq_ctx = NULL;
  int rc = ibv_get_cq_event((*conn_ctx)->id->send_cq_channel, &ev_cq, &cq_ctx);
  if (G_UNLIKELY(rc != 0))
    return 0; // EAGAIN, effectively

  (*conn_ctx)->num_not_ack++;
  ack_completions(*conn_ctx, (*conn_ctx)->min_ack);

  rc = ibv_req_notify_cq(ev_cq, 0);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_req_notify_cq");
    return rc;
  }

  return poll_completions(context, *conn_ctx, reqs, error_record);
}

static int
on_read_completion(struct spectrum_reader_context_ *context, unsigned pfd,
                   struct vys_error_record **error_record)
{
  struct pollfd *pollfd =
    &g_array_index(context->pollfds, struct pollfd, pfd);

  GSList *reqs = NULL;
  struct server_connection_context *conn_ctx;
  int rc = get_completed_requests(context, pollfd->fd, &conn_ctx, &reqs,
                                  error_record);
  if (G_UNLIKELY(rc != 0))
    return rc;
  if (G_UNLIKELY(reqs == NULL))
    return 0;

  g_timer_start(conn_ctx->last_access);

  rc = post_server_reads(context, conn_ctx, error_record);
  if (G_UNLIKELY(rc != 0)) return rc;

  while (reqs != NULL) {
    struct rdma_req *req = reqs->data;
    struct rdma_req_block *rblk = RDMA_REQ_BLOCK_P(req);
    switch (req->result) {
    case RDMA_REQ_ID_VERIFICATION_FAILURE:
      convert_valid_to_id_failure(rblk->message, req->index);
      break;
    case RDMA_REQ_READ_FAILURE:
      convert_valid_to_rdma_read_failure(
        rblk->message, req->index, req->status);
      break;
    default:
      break;
    }
    fulfill_rdma_req(context, req);
    reqs = g_slist_delete_link(reqs, reqs);
  }

  if (!conn_ctx->established && conn_ctx->num_posted_wr == 0)
    rc = complete_server_disconnect(context, conn_ctx, error_record);

  return rc;
}

static int
on_inactivity_timer_event(struct spectrum_reader_context_ *context,
                          struct vys_error_record **error_record)
{
  struct pollfd *pollfd = &g_array_index(
    context->pollfds, struct pollfd, INACTIVITY_TIMER_FD_INDEX);

  uint64_t n;
  read(pollfd->fd, &n, sizeof(n));

  double inactive_server_timeout_sec =
    context->shared->handle->config.inactive_server_timeout_sec;

  struct vys_error_record *er = NULL;
  void disconnect_inactive(struct sockaddr_in *unused,
                           struct server_connection_context *conn_ctx,
                           void *unused1) {
    if (g_timer_elapsed(conn_ctx->last_access, NULL)
        >= inactive_server_timeout_sec)
      begin_server_disconnect(context, conn_ctx, &er);
  }

  g_hash_table_foreach(
    context->connections, (GHFunc)disconnect_inactive, NULL);

  *error_record = vys_error_record_concat(er, *error_record);
  return (er == NULL) ? 0 : -1;
}

static int
on_buffer_pool_idle_timer_event(struct spectrum_reader_context_ *context,
                                struct vys_error_record **error_record)
{
  struct pollfd *pollfd = &g_array_index(context->pollfds, struct pollfd,
                                         BUFFER_POOL_IDLE_TIMER_FD_INDEX);
  uint64_t n;
  read(pollfd->fd, &n, sizeof(n));

  void remove_idle(struct spectrum_buffer_pool *pool,
                   struct vys_error_record **er) {
    deregister_one_spectrum_buffer_pool(pool, context->mrs, er);
  }

  struct vys_error_record *er = NULL;
  context->shared->handle->remove_idle_pools_fn(
    context->shared->handle, remove_idle, &er);

  *error_record = vys_error_record_concat(er, *error_record);
  return (er == NULL) ? 0: -1;
}

static int
on_poll_events(struct spectrum_reader_context_ *context,
               struct vys_error_record **error_record)
{
  /* inactivity timer events */
  int rc1 = 0;
  struct pollfd *tm_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            INACTIVITY_TIMER_FD_INDEX);
  if (tm_pollfd->fd >= 0 && tm_pollfd->revents & POLLIN)
    rc1 = on_inactivity_timer_event(context, error_record);

  /* read completion events */
  int rc2 = 0;
  for (unsigned i = NUM_FIXED_FDS; i < context->pollfds->len; ++i) {
    struct pollfd *ev_pollfd =
      &g_array_index(context->pollfds, struct pollfd, i);
    int rc3 = 0;
    if (ev_pollfd->fd >= 0 && ev_pollfd->revents & POLLIN) {
      rc3 = on_read_completion(context, i, error_record);
    } else if (ev_pollfd->revents & (POLLERR | POLLHUP)) {
      MSG_ERROR(error_record, -1, "%s",
                "connection event channel ERR or HUP");
      rc3 = -1;
    }
    if (G_UNLIKELY(rc2 == 0 && rc3 != 0)) rc2 = rc3;
  }

  /* read request events */
  int rc4 = 0;
  struct pollfd *rr_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            READ_REQUEST_QUEUE_FD_INDEX);
  if (rr_pollfd->fd >= 0 && rr_pollfd->revents & POLLIN) {
    struct data_path_message *msg =
      vys_async_queue_pop(context->shared->read_request_queue);
    if (msg != NULL)
      rc4 = on_data_path_message(context, msg, error_record);
  }

  /* buffer pool idle timer events */
  int rc5 = 0;
  struct pollfd *bp_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            BUFFER_POOL_IDLE_TIMER_FD_INDEX);
  if (bp_pollfd->fd >= 0 && bp_pollfd->revents & POLLIN)
    rc5 = on_buffer_pool_idle_timer_event(context, error_record);

  /* cm events */
  int rc6 = 0;
  struct pollfd *cm_pollfd =
    &g_array_index(context->pollfds, struct pollfd, CM_EVENT_FD_INDEX);
  if (cm_pollfd->fd >= 0 && cm_pollfd->revents & POLLIN) {
    rc6 = on_cm_event(context, error_record);
  } else if (cm_pollfd->revents & (POLLERR | POLLHUP)) {
    MSG_ERROR(error_record, -1, "%s",
              "rdma cm event channel ERR or HUP");
    rc6 = -1;
  }

  if (context->new_pollfds->len > 0) {
    GArray *tmp = context->pollfds;
    context->pollfds = context->new_pollfds;
    context->new_pollfds = tmp;
    g_array_set_size(context->new_pollfds, 0);
  }

  int rc;
  if (G_UNLIKELY(rc1 != 0)) rc = rc1;
  else if (G_UNLIKELY(rc2 != 0)) rc = rc2;
  else if (G_UNLIKELY(rc4 != 0)) rc = rc4;
  else if (G_UNLIKELY(rc5 != 0)) rc = rc5;
  else if (G_UNLIKELY(rc6 != 0)) rc = rc6;
  else rc = 0;
  return rc;
}

static int
to_quit_state(struct spectrum_reader_context_ *context,
              struct data_path_message *quit_msg,
              struct vys_error_record **error_record)
{
  int rc = 0;
  if (context->state != STATE_QUIT && context->state != STATE_DONE) {
    if (context->fd_connections != NULL) {
      GSequenceIter *iter =
        g_sequence_get_begin_iter(context->fd_connections);
      while (!g_sequence_iter_is_end(iter)) {
        struct server_connection_context *conn_ctx = g_sequence_get(iter);
        begin_server_disconnect(context, conn_ctx, error_record);
        iter = g_sequence_iter_next(iter);
      }
    }
    if (quit_msg == NULL) {
      quit_msg = data_path_message_new(context->shared->handle);
      if (quit_msg != NULL)
        quit_msg->typ = DATA_PATH_QUIT;
    }
    context->state = STATE_QUIT;
    context->quit_msg = quit_msg;
    if (quit_msg != NULL)
      rc = loopback_msg(context, quit_msg, error_record);
  }
  return rc;
}

static int
spectrum_reader_loop(struct spectrum_reader_context_ *context,
                     struct vys_error_record **error_record)
{
  int result = 0;
  GTimer *req_backlog_timer = g_timer_new();
  unsigned long acc_req_backlog = 0;
  unsigned num_req_backlog_samples = 0;
  bool startup_sync = FALSE;
  bool quit = FALSE;
  while (!quit) {
    int rc = 0;
    int nfd = poll((struct pollfd *)(context->pollfds->data),
                   context->pollfds->len, 1);
    if (G_LIKELY(nfd > 0)) {
      rc = on_poll_events(context, error_record);
    } else if (G_UNLIKELY(nfd < 0 && errno != EINTR)) {
      MSG_ERROR(error_record, errno,
                "spectrum_reader poll failed: %s", strerror(errno));
      rc = -1;
    }
    if (G_UNLIKELY(rc != 0)) {
      to_quit_state(context, NULL, error_record);
      result = -1;
    }
    quit = (context->state == STATE_DONE
            && (context->connections == NULL
              || g_hash_table_size(context->connections) == 0));

    // keep rdma request backlog statistics; not currently used for any purpose
    // but debugging, but it might be useful, so leaving the code in place
    acc_req_backlog += context->rdma_req_backlog;
    ++num_req_backlog_samples;
    gdouble elapsed = g_timer_elapsed(req_backlog_timer, NULL);
    if (elapsed >= 1.0 /* TODO: make configurable */) {
      g_timer_start(req_backlog_timer);
      /* printf( */
      /*   "rdma backlog %g\n", */
      /*   (double)acc_req_backlog / num_req_backlog_samples); */
      acc_req_backlog = 0;
      num_req_backlog_samples = 0;
    }
    if (G_UNLIKELY(!startup_sync)) {
      startup_sync = TRUE;
      quit = sync_startup_phase(context->shared->handle, false);
    }
  }
  return result;
}

static int
start_inactivity_timer(struct spectrum_reader_context_ *context,
                       struct vys_error_record **error_record)
{
  struct pollfd *tm_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            INACTIVITY_TIMER_FD_INDEX);

  tm_pollfd->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  tm_pollfd->events = POLLIN;
  if (tm_pollfd->fd >= 0) {
    time_t sec =
      context->shared->handle->config.inactive_server_timeout_sec / 2;
    struct itimerspec itimerspec = {
      .it_interval = { .tv_sec = sec, .tv_nsec = 0 },
      .it_value = { .tv_sec = sec, .tv_nsec = 0 }
    };
    int rc = timerfd_settime(tm_pollfd->fd, 0, &itimerspec, NULL);
    if (rc < 0) {
      MSG_ERROR(error_record, errno,
                "Failed to start inactivity timer: %s",
                strerror(errno));
      stop_inactivity_timer(context, error_record);
      return rc;
    }
  } else {
    MSG_ERROR(error_record, errno, "Failed to create inactivity timer: %s",
              strerror(errno));
  }
  return tm_pollfd->fd;
}

static int
stop_inactivity_timer(struct spectrum_reader_context_ *context,
                      struct vys_error_record **error_record)
{
  struct pollfd *tm_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            INACTIVITY_TIMER_FD_INDEX);
  int rc = 0;
  if (tm_pollfd->fd >= 0) {
    rc = close(tm_pollfd->fd);
    if (rc < 0)
      MSG_ERROR(error_record, errno,
                "Failed to close inactivity timer: %s", strerror(errno));
  }
  return rc;
}

static int
start_buffer_pool_idle_timer(struct spectrum_reader_context_ *context,
                             struct vys_error_record **error_record)
{
  struct pollfd *tm_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            BUFFER_POOL_IDLE_TIMER_FD_INDEX);

  tm_pollfd->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  tm_pollfd->events = POLLIN;
  if (tm_pollfd->fd >= 0) {
    time_t sec =
      context->shared->handle->config
      .spectrum_buffer_pool_min_idle_lifetime_sec;
    struct itimerspec itimerspec = {
      .it_interval = { .tv_sec = sec, .tv_nsec = 0 },
      .it_value = { .tv_sec = sec, .tv_nsec = 0 }
    };
    int rc = timerfd_settime(tm_pollfd->fd, 0, &itimerspec, NULL);
    if (rc < 0) {
      MSG_ERROR(error_record, errno,
                "Failed to start buffer pool idle timer: %s",
                strerror(errno));
      stop_buffer_pool_idle_timer(context, error_record);
      return rc;
    }
  } else {
    MSG_ERROR(error_record, errno,
              "Failed to create buffer pool idle timer: %s",
              strerror(errno));
  }
  return tm_pollfd->fd;
}

static int
stop_buffer_pool_idle_timer(struct spectrum_reader_context_ *context,
                            struct vys_error_record **error_record)
{
  struct pollfd *tm_pollfd = &g_array_index(context->pollfds, struct pollfd,
                                            BUFFER_POOL_IDLE_TIMER_FD_INDEX);
  int rc = 0;
  if (tm_pollfd->fd >= 0) {
    rc = close(tm_pollfd->fd);
    if (rc < 0)
      MSG_ERROR(error_record, errno,
                "Failed to close buffer pool idle timer: %s",
                strerror(errno));
  }
  return rc;
}

static int
start_read_request_poll(struct spectrum_reader_context_ *context,
                        struct vys_error_record **error_record)
{
  struct pollfd *qpfd = &g_array_index(context->pollfds, struct pollfd,
                                       READ_REQUEST_QUEUE_FD_INDEX);
  qpfd->fd = vys_async_queue_pop_fd(context->shared->read_request_queue);
  qpfd->events = POLLIN;
  return 0;
}

static int
stop_read_request_poll(struct spectrum_reader_context_ *context,
                       struct vys_error_record **error_record)
{
  struct pollfd *qpfd = &g_array_index(context->pollfds, struct pollfd,
                                       READ_REQUEST_QUEUE_FD_INDEX);
  qpfd->fd = -1;
  return 0;
}

static int
loopback_msg(struct spectrum_reader_context_ *context,
             struct data_path_message *msg,
             struct vys_error_record **error_record)
{
  int result = 0;
  ssize_t num_written = 0;
  do {
    ssize_t n = write(context->shared->loop_fd, (void *)&msg + num_written,
                      sizeof(msg) - num_written);
    if (G_LIKELY(n >= 0)) {
      num_written += n;
    } else if (errno != EINTR && n < 0) {
      MSG_ERROR(error_record, errno, "Failed to write to loop pipe: %s",
                strerror(errno));
      result = -1;
    }
  } while (num_written < sizeof(msg) && result == 0);

  return result;
}

void *
spectrum_reader(struct spectrum_reader_context *shared)
{
  struct vys_error_record *error_record = NULL;
  bool failed = FALSE;

  int rc = 0;
  struct spectrum_reader_context_ context;
  memset(&context, 0, sizeof(context));
  context.shared = shared;
  context.state = STATE_INIT;
  context.pollfds = g_array_new(false, false, sizeof(struct pollfd));
  context.new_pollfds = g_array_new(false, false, sizeof(struct pollfd));
  data_path_message_pool_ref(context.shared->handle);
  /* create table for registered memory keys */
  context.mrs = g_hash_table_new_full(
    g_direct_hash, g_direct_equal,
    (GDestroyNotify)spectrum_buffer_pool_unref,
    NULL);
  if (G_UNLIKELY(context.mrs == NULL)) {
    MSG_ERROR(&error_record, -1,
              "Failed to allocate buffer pool hash table");
    goto cleanup_and_return;
  }

  g_array_set_size(context.pollfds, NUM_FIXED_FDS);
  for (unsigned i = 0; i < NUM_FIXED_FDS; ++i) {
    struct pollfd *pollfd =
      &g_array_index(context.pollfds, struct pollfd, i);
    pollfd->fd = -1;
    pollfd->events = 0;
  }

  rc = start_rdma_cm(&context, &error_record);
  if (rc < 0)
    goto cleanup_and_return;

  rc = start_inactivity_timer(&context, &error_record);
  if (rc < 0)
    goto cleanup_and_return;

  rc = start_buffer_pool_idle_timer(&context, &error_record);
  if (rc < 0)
    goto cleanup_and_return;

  rc = start_read_request_poll(&context, &error_record);
  if (rc != 0)
    goto cleanup_and_return;

  context.state = STATE_RUN;
  while (!failed &&
         g_atomic_int_get(&shared->handle->barrier.phase)
         < PHASE_SPECTRUM_READER_STARTED)
    failed = sync_startup_phase(shared->handle, false);
  if (!failed)
    rc = spectrum_reader_loop(&context, &error_record);

cleanup_and_return:
  while (!failed &&
         g_atomic_int_get(&shared->handle->barrier.phase)
         <= PHASE_SPECTRUM_READER_STARTED)
    failed = sync_startup_phase(shared->handle, rc != 0);

  /* initialization failures may result in not being in STATE_DONE state */
  if (context.state != STATE_DONE) {
    to_quit_state(&context, NULL, &error_record);
    /* polling loop will only poll the loop fd, as the others are now
     * closed */
    spectrum_reader_loop(&context, &error_record);
  }

  stop_read_request_poll(&context, &error_record);

  stop_buffer_pool_idle_timer(&context, &error_record);

  stop_inactivity_timer(&context, &error_record);

  stop_rdma_cm(&context, &error_record);

  rc = close(shared->loop_fd);
  if (rc != 0)
    MSG_ERROR(&error_record, errno, "Failed to close loop fd: %s",
              strerror(errno));

//  g_assert(context.end_msg != NULL && context.end_msg->typ == DATA_PATH_END);
  if (context.end_msg != NULL) {
    error_record =
      vys_error_record_concat(error_record, context.end_msg->error_record);
    vys_error_record_free(context.end_msg->error_record);
    context.end_msg->error_record = NULL;
  }

  if (context.mrs != NULL) g_hash_table_destroy(context.mrs);

  /* create vysmaw_message for end result */
  struct vysmaw_result result;
  if (error_record == NULL) {
    result.code = VYSMAW_NO_ERROR;
    result.syserr_desc = NULL;
  } else {
    result.code = VYSMAW_SYSERR;
    result.syserr_desc = vys_error_record_to_string(&error_record);
  }
  struct vysmaw_message *msg = end_message_new(shared->handle, &result);

  /* post result message consumer queue */
  post_msg(shared->handle, msg);
  if (context.end_msg != NULL)
    data_path_message_free(shared->handle, context.end_msg);

  while (context.free_rdma_req_blocks != NULL) {
    --(context.num_free_rdma_req_blocks);
    g_slice_free1(
      SIZEOF_RDMA_REQ_BLOCK(context.shared->handle->signal_msg_num_spectra),
      context.free_rdma_req_blocks->data);
    context.free_rdma_req_blocks =
      g_slist_delete_link(
        context.free_rdma_req_blocks,
        context.free_rdma_req_blocks);
  }
  if (context.num_free_rdma_req_blocks != 0)
    g_warning(
      "rdma_req_blocks num_alloc - num_free: %ld",
      context.num_free_rdma_req_blocks);

  data_path_message_pool_unref(context.shared->handle);
  handle_unref(shared->handle); // end message has been posted

  g_array_free(context.pollfds, TRUE);
  g_array_free(context.new_pollfds, TRUE);
  vys_async_queue_unref(shared->read_request_queue);
  g_free(shared);
  return NULL;
}



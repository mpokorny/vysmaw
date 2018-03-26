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
#include <mpi.h>
#include <vys.h>
#include <poll.h>
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <locale.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <sys/timerfd.h>
#include <vys_buffer_pool.h>

#if GLIB_CHECK_VERSION(2,32,0)
# define THREAD_INIT while (false)
# define THREAD_NEW(name, func, data) g_thread_new((name), (func), (data))
# define Mutex GMutex
# define MUTEX_INIT(m) g_mutex_init(&(m))
# define MUTEX_CLEAR(m) g_mutex_clear(&(m))
# define MUTEX_LOCK(m) g_mutex_lock(&(m))
# define MUTEX_UNLOCK(m) g_mutex_unlock(&(m))
# define RecMutex GRecMutex
# define REC_MUTEX_INIT g_rec_mutex_init
# define REC_MUTEX_CLEAR g_rec_mutex_clear
# define REC_MUTEX_LOCK g_rec_mutex_lock
# define REC_MUTEX_UNLOCK g_rec_mutex_unlock
# define Cond GCond
# define COND_INIT(c) g_cond_init(&(c))
# define COND_CLEAR(c) g_cond_clear(&(c))
# define COND_WAIT(c, m) g_cond_wait(&(c), &(m))
# define COND_SIGNAL(c) g_cond_signal(&(c))
#else
# define THREAD_INIT g_thread_init(NULL)
# define THREAD_NEW(name, func, data) ({                                \
      GError *_err = NULL;                                              \
      GThread *_result = g_thread_create((func), (data), true, &_err);  \
      if (_err != NULL) {                                               \
        g_error("Failed to start thread: %s", _err->message);           \
        g_error_free(_err);                                             \
      }                                                                 \
      _result; })
# define Mutex GMutex *
# define MUTEX_INIT(m) { m = g_mutex_new(); }
# define MUTEX_CLEAR(m) { if ((m) != NULL) g_mutex_free(m); }
# define MUTEX_LOCK(m) { if ((m) != NULL) g_mutex_lock(m); }
# define MUTEX_UNLOCK(m) { if ((m) != NULL) g_mutex_unlock(m); }
# define RecMutex GStaticRecMutex
# define REC_MUTEX_INIT g_static_rec_mutex_init
# define REC_MUTEX_CLEAR g_static_rec_mutex_free
# define REC_MUTEX_LOCK g_static_rec_mutex_lock
# define REC_MUTEX_UNLOCK g_static_rec_mutex_unlock
# define Cond GCond *
# define COND_INIT(c) { c = g_cond_new(); }
# define COND_CLEAR(c) { if ((c) != NULL) g_cond_free(c); }
# define COND_WAIT(c, m) { if ((c) != NULL && (m) != NULL) g_cond_wait(c, m); }
# define COND_SIGNAL(c) { if ((c) != NULL) g_cond_signal(c); }
#endif

#define NUM_BASELINES(na) (((na) * ((na) - 1)) / 2)

#define DEFAULT_NUM_ANTENNAS 27
#define DEFAULT_NUM_SPECTRAL_WINDOWS 4
#define DEFAULT_NUM_CHANNELS 64
#define DEFAULT_NUM_POLPRODS 2
#define DEFAULT_INTEGRATION_TIME_MICROSEC 100000
#define DEFAULT_SIGNAL_MSG_NUM_SPECTRA 32
#define DEFAULT_DATA_BUFFER_LENGTH_SEC 5

#define RESOLVE_ADDR_TIMEOUT_MS 1000
#define LISTEN_BACKLOG 8
#define SIGNAL_MSG_MAX_POSTED 1000
#define SIGNAL_MSG_QUEUE_LENGTH (2 * SIGNAL_MSG_MAX_POSTED)
#define SIGNAL_MSG_BLOCK_LENGTH (4 * SIGNAL_MSG_QUEUE_LENGTH)
#define MAX_POLPRODS_INDICES 4

#define CM_EVENT_FD 0
#define MULTICAST_EVENT_FD 1
#define TIMER_EVENT_FD 2
#define NUM_EVENT_FDS 3

#define VYSSIM_ARG_ERROR vyssim_arg_error_quark()

struct spectral_window_descriptor {
  unsigned index;
  uint8_t num_polprods_indices;
  unsigned polprods_indices[MAX_POLPRODS_INDICES];
};

struct client_connection_context {
  struct rdma_cm_id *id;
  struct ibv_mr *mr;
  bool established;
};

struct dataset_parameters {
  unsigned num_antennas;
  unsigned num_spectral_windows;
  unsigned num_polprods;
  unsigned num_channels;
  unsigned integration_time_microsec;
};

struct mcast_context {
  struct sockaddr sockaddr;
  struct rdma_cm_id *id;
  struct rdma_event_channel *event_channel;
  struct ibv_comp_channel *comp_channel;
  struct ibv_pd *pd;
  struct ibv_cq *cq;
  struct ibv_ah *ah;
  uint32_t remote_qpn;
  uint32_t remote_qkey;
  struct ibv_mr *mr;
  struct vys_buffer_pool *signal_msg_pool;
  unsigned signal_msg_num_spectra;
  unsigned num_wr;
  unsigned max_wr;
  unsigned num_not_ack;
  unsigned min_ack;
  struct ibv_wc *wc;
};

struct server_context {
  struct sockaddr sockaddr;
  struct rdma_cm_id *id;
  struct rdma_event_channel *event_channel;
  struct ibv_comp_channel *comp_channel;
  GArray *restrict pollfds;

  GThread *gen_thread;

  struct vys_signal_msg *queue[SIGNAL_MSG_QUEUE_LENGTH];
  unsigned num_queued;
  Mutex queue_mutex;
  Cond queue_changed_condition;

  GSList *connections;

  unsigned num_data_buffers;
  size_t data_buffer_block_size;
  gchar *data_buffer_block;
  unsigned data_buffer_index;
  unsigned data_buffer_len;

  size_t total_size_per_signal;
};

struct vyssim_context {
  char *bind_addr;
  struct sockaddr_in sockaddr;
  struct mcast_context mcast_ctx;
  struct server_context server_ctx;
  struct dataset_parameters params;
  struct vys_configuration *vconfig;

  MPI_Comm comm;

  uint64_t epoch_ms;
  unsigned data_buffer_length_sec;
  GArray *spw_descriptors;
};

enum vyssim_arg_error {
  VYSSIM_ARG_ERROR_PARSE,
  VYSSIM_ARG_ERROR_RANGE
};

static GQuark vyssim_arg_error_quark(void) __attribute__((pure));
static void param_set_unsigned(
  GHashTable *params, const gchar *name, unsigned value)
  __attribute__((nonnull));
static int set_nonblocking(int fd);
static struct vys_signal_msg *gen_one_signal_msg(
  struct vyssim_context *vyssim, guint32 *id_num,
  guint64 timestamp_us, unsigned ant0, unsigned ant1,
  unsigned spectral_window_index, unsigned polprods_index)
  __attribute__((nonnull,returns_nonnull));
static void *data_generator(struct vyssim_context *vyssim)
  __attribute__((nonnull));
static int resolve_addr(
  struct vyssim_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull(1)));
static int get_cm_event(
  struct rdma_event_channel *channel, enum rdma_cm_event_type type,
  struct rdma_cm_event **out_ev, struct vys_error_record **error_record)
  __attribute__((nonnull(1)));
static int create_mcast_resources(
  struct mcast_context *ctx, struct vys_error_record **error_record)
  __attribute__((nonnull(1)));
static int init_multicast(
  struct vyssim_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull(1)));
static unsigned num_spectra_per_integration_per_baseline(
  const struct vyssim_context *vyssim)
  __attribute__((nonnull,pure));
static int init(
  struct vyssim_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int start_send_timer(
  struct vyssim_context *vyssim, struct pollfd *pfd,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int stop_send_timer(int fd, struct vys_error_record **error_record);
static int on_client_connect(
  struct server_context *server_ctx, struct rdma_cm_id *id,
  struct rdma_conn_param *conn_param, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int begin_client_disconnect(
  struct server_context *server_ctx, GSList *connection_node,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int complete_client_disconnect(
  struct server_context *server_ctx, GSList *connection_node,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int compare_client_connection_context(
  const struct client_connection_context *ctx, const struct rdma_cm_id *id)
  __attribute__((nonnull,pure));
static int on_cm_event(
  struct server_context *server_ctx, struct vys_error_record **error_record)
  __attribute__((nonnull(1)));
static int on_mc_event(
  struct mcast_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int handle_timer_event(
  struct vyssim_context *vyssim, uint64_t *num_events,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static int on_timer_event(
  struct vyssim_context *vyssim_context,
  struct vys_error_record **error_record, int timerfd, uint64_t *backlog)
  __attribute__((nonnull));
static int send_msgs(
  struct vyssim_context *vyssim_context,
  struct vys_error_record **error_record)
  __attribute__((nonnull));
static void ack_and_drain_cq(
  unsigned num_to_ack, unsigned num_wr, struct ibv_cq *cq)
  __attribute__((nonnull));
static int destroy_mcast_resources(
  struct mcast_context *ctx, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int fin_multicast(
  struct vyssim_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int fin(
  struct vyssim_context *vyssim, struct vys_error_record **error_record)
  __attribute__((nonnull));
static int run(struct vyssim_context *vyssim)
  __attribute__((nonnull));
static void push_msg_to_queue(
  struct vyssim_context *vyssim, struct vys_signal_msg *msg)
  __attribute__((nonnull));
static struct vys_signal_msg *pop_msg_from_queue(
  struct vyssim_context *vyssim)
  __attribute__((nonnull,returns_nonnull));
static void free_signal_msg(
  struct mcast_context *ctx, struct vys_signal_msg *msg)
  __attribute__((nonnull));
static gboolean parse_param(
  const gchar *option_name, const gchar *value, GHashTable *params,
  GError **error)
  __attribute__((nonnull));
static gchar * add_param(
  GHashTable *params, const gchar *lname, const gchar *sname,
  guint value, const gchar *desc, unsigned *where)
  __attribute__((nonnull,returns_nonnull,malloc));
static bool parse_options(
  int *argc, char **argv[], unsigned *num_antennas,
  unsigned *num_spectral_windows, unsigned *num_channels,
  unsigned *num_polprods, unsigned *integration_time_microsec,
  unsigned *signal_msg_num_spectra, unsigned *data_buffer_length_sec,
  char **vys_configuration_path, GError **error)
  __attribute__((nonnull));

static char num_antennas_lname[] = "num-antennas";
static char num_antennas_sname[] = "a";
static char num_spectral_windows_lname[] = "num-spectral-windows";
static char num_spectral_windows_sname[] = "w";
static char num_channels_lname[] = "num-channels";
static char num_channels_sname[] = "c";
static char num_polprods_lname[] = "num-polprods";
static char num_polprods_sname[] = "p";
static char integration_time_microsec_lname[] = "integration-time";
static char integration_time_microsec_sname[] = "i";
static char signal_msg_num_spectra_lname[] = "signal-message-length";
static char signal_msg_num_spectra_sname[] = "l";
static char data_buffer_length_sec_lname[] = "data-buffer-duration";
static char data_buffer_length_sec_sname[] = "f";
static char vys_configuration_path_lname[] = "vys";
static char vys_configuration_path_sname[] = "v";
static char summary[] =
  "Distributed visibility stream simulator.\n"
  "\n"
  "This application is an MPI application. It may be run as a single\n"
  "process, or as a set of multiple processes using an MPI job\n"
  "launcher. Each of the spawned processes is multi-threaded; the\n"
  "application requires an MPI thread level of MPI_THREAD_FUNNELED\n"
  "or better to run. You must ensure that the application is started so\n"
  "that the thread level requirement is met, whether or not the MPI job\n"
  "launcher is used.";

static GQuark
vyssim_arg_error_quark(void)
{
  return g_quark_from_static_string("vyssim-arg-error-quark");
}

static void
param_set_unsigned(GHashTable *params, const gchar *name, unsigned value)
{
  unsigned *p = g_hash_table_lookup(params, (gchar *)name);
  *p = value;
}

static int
set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL);
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void
free_signal_msg(struct mcast_context *ctx, struct vys_signal_msg *msg)
{
  vys_buffer_pool_push(ctx->signal_msg_pool, msg);
}

static void
push_msg_to_queue(struct vyssim_context *vyssim, struct vys_signal_msg *msg)
{
  struct server_context *ctx = &(vyssim->server_ctx);
  /* call this only when ctx->queue_mutex is locked by caller */
  while (ctx->num_queued == SIGNAL_MSG_QUEUE_LENGTH)
    COND_WAIT(ctx->queue_changed_condition, ctx->queue_mutex);
  ctx->queue[ctx->num_queued++] = msg;
  COND_SIGNAL(ctx->queue_changed_condition);
}

static struct vys_signal_msg *
pop_msg_from_queue(struct vyssim_context *vyssim)
{
  struct server_context *ctx = &(vyssim->server_ctx);
  MUTEX_LOCK(ctx->queue_mutex);
  while (ctx->num_queued == 0)
    COND_WAIT(ctx->queue_changed_condition, ctx->queue_mutex);
  struct vys_signal_msg *result = ctx->queue[0];
  ctx->num_queued--;
  memmove(&(ctx->queue[0]), &(ctx->queue[1]),
          ctx->num_queued * sizeof(struct vys_signal_msg *));
  COND_SIGNAL(ctx->queue_changed_condition);
  MUTEX_UNLOCK(ctx->queue_mutex);
  return result;
}

static struct vys_signal_msg *
gen_one_signal_msg(struct vyssim_context *vyssim, guint32 *id_num,
                   guint64 timestamp_us, unsigned ant0, unsigned ant1,
                   unsigned spectral_window_index, unsigned polprods_index)
{
  static gchar *config_id = NULL;
  if (G_UNLIKELY(config_id == NULL))
    config_id = g_strdup_printf("%s-%i", g_get_prgname(), getpid());
  struct mcast_context *mcast_ctx = &(vyssim->mcast_ctx);
  struct server_context *server_ctx = &(vyssim->server_ctx);

  struct vys_signal_msg *result =
    vys_buffer_pool_pop(mcast_ctx->signal_msg_pool);
  struct vys_signal_msg_payload *payload = &(result->payload);
  vys_signal_msg_payload_init(payload, config_id);
  payload->sockaddr = vyssim->sockaddr;
  payload->mr_id = 0;
  payload->num_channels = vyssim->params.num_channels;
  payload->bin_stride = payload->num_channels;
  payload->num_bins = 1;
  payload->stations[0] = ant0;
  payload->stations[1] = ant1;
  payload->spectral_window_index = spectral_window_index;
  payload->baseband_id = 0;
  payload->polarization_product_id = polprods_index;
  payload->num_spectra = mcast_ctx->signal_msg_num_spectra;
  for (unsigned n = 0; n < mcast_ctx->signal_msg_num_spectra; ++n) {
    struct vys_spectrum_info *info = &(payload->infos[n]);
    gchar *buff =
      &(server_ctx->data_buffer_block[server_ctx->data_buffer_index *
                                      server_ctx->data_buffer_len]);
    info->data_addr = (uint64_t)buff;
    info->timestamp =
      1000 * (timestamp_us + n * vyssim->params.integration_time_microsec);
    info->id_num = *id_num;
    __sync_lock_test_and_set((guint32 *)buff, *id_num);
    *id_num += 1;
    buff += VYS_SPECTRUM_OFFSET;
    /* partially fill buffer */
    gfloat *fbuff = (gfloat *)buff;
    *fbuff++ = (float)info->timestamp;
    *fbuff++ = (float)vyssim->params.num_channels;
    *fbuff++ = (float)ant0;
    *fbuff++ = (float)ant1;
    *fbuff++ = (float)spectral_window_index;
    *fbuff++ = (float)polprods_index;
    server_ctx->data_buffer_index =
      (server_ctx->data_buffer_index + 1) % server_ctx->num_data_buffers;
  }
  return result;
}

static void *
data_generator(struct vyssim_context *vyssim)
{
  guint32 id_num = 0;
  struct server_context *ctx = &(vyssim->server_ctx);
  guint64 epoch_microsec = 1000 * vyssim->epoch_ms;
  bool quit = false;
  for (unsigned intg = 0; !quit;
       intg += vyssim->mcast_ctx.signal_msg_num_spectra) {
    guint64 t_us =
      intg * vyssim->params.integration_time_microsec + epoch_microsec;
    for (unsigned a0 = 0; !quit && a0 < vyssim->params.num_antennas; ++a0) {
      for (unsigned a1 = a0 + 1;
           !quit && a1 < vyssim->params.num_antennas;
           ++a1) {
        for (unsigned spw_idx = 0;
             !quit && spw_idx < vyssim->spw_descriptors->len;
             ++spw_idx){
          struct spectral_window_descriptor *spw_desc =
            &g_array_index(vyssim->spw_descriptors,
                           struct spectral_window_descriptor,
                           spw_idx);
          for (unsigned pp_idx = 0;
               !quit && pp_idx < spw_desc->num_polprods_indices;
               ++pp_idx) {
            unsigned pp = spw_desc->polprods_indices[pp_idx];
            MUTEX_LOCK(ctx->queue_mutex);
            if (vyssim->mcast_ctx.signal_msg_num_spectra == 0) {
              quit = true;
            } else {
              push_msg_to_queue(
                vyssim,
                gen_one_signal_msg(
                  vyssim, &id_num, t_us, a0 + 1, a1 + 1,
                  spw_desc->index, pp));
            }
            MUTEX_UNLOCK(ctx->queue_mutex);
          }
        }

      }
    }
  }
  return NULL;
}

static int
resolve_addr(struct vyssim_context *vyssim,
             struct vys_error_record **error_record)
{
  int rc;
  struct mcast_context *ctx = &(vyssim->mcast_ctx);
  struct rdma_addrinfo *bind_rai = NULL;
  struct rdma_addrinfo *mcast_rai = NULL;
  struct rdma_addrinfo hints;

  memset(&hints, 0, sizeof (hints));

  hints.ai_port_space = RDMA_PS_UDP;
  hints.ai_flags = RAI_PASSIVE;
  rc = rdma_getaddrinfo(vyssim->bind_addr, NULL, &hints, &bind_rai);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_getaddrinfo (bind)");
    return rc;
  }

  /* bind to a specific adapter if requested to do so */
  rc = rdma_bind_addr(ctx->id, bind_rai->ai_src_addr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_bind_addr");
    return rc;
  }

  hints.ai_flags = 0;
  rc = rdma_getaddrinfo(vyssim->vconfig->signal_multicast_address, NULL,
                        &hints, &mcast_rai);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_getaddrinfo (mcast)");
    return rc;
  }

  rc = rdma_resolve_addr(
    ctx->id, bind_rai->ai_src_addr, mcast_rai->ai_dst_addr,
    RESOLVE_ADDR_TIMEOUT_MS);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_resolve_addr");
    return rc;
  }

  rc = get_cm_event(
    ctx->event_channel, RDMA_CM_EVENT_ADDR_RESOLVED, NULL, error_record);
  if (G_UNLIKELY(rc != 0))
    return rc;

  memcpy(&ctx->sockaddr, mcast_rai->ai_dst_addr,
         sizeof(struct sockaddr));

  return 0;
}

static int
get_cm_event(struct rdma_event_channel *channel,
             enum rdma_cm_event_type type,
             struct rdma_cm_event **out_ev,
             struct vys_error_record **error_record)
{
  struct rdma_cm_event *event = NULL;

  int rc = rdma_get_cm_event(channel, &event);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_get_cm_event");
    return -1;
  }

  /* Verify the event is the expected type */
  if (event->event != type) {
    MSG_ERROR(error_record, -1, "event: %s, expecting: %s, status: %s",
              rdma_event_str(event->event), rdma_event_str(type),
              strerror(-event->status));
    rc = -1;
  }

  /* Pass the event back to the user if requested */
  if (out_ev == NULL)
    rdma_ack_cm_event(event);
  else
    *out_ev = event;

  return rc;
}

static int
create_mcast_resources(struct mcast_context *ctx,
                       struct vys_error_record **error_record)
{
  g_assert(ctx->id->pd != NULL);
  ctx->cq = ibv_create_cq(ctx->id->verbs, ctx->max_wr, NULL,
                          ctx->comp_channel, 0);
  if (G_UNLIKELY(ctx->cq == NULL)) {
    VERB_ERR(error_record, errno, "ibv_create_cq");
    return -1;
  }

  struct ibv_qp_init_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.qp_type = IBV_QPT_UD;
  attr.send_cq = ctx->cq;
  attr.recv_cq = ctx->cq;
  attr.sq_sig_all = 1;
  attr.cap.max_send_wr = ctx->max_wr;
  attr.cap.max_recv_wr = 1;
  attr.cap.max_send_sge = 1;
  attr.cap.max_recv_sge = 1;
  int rc = rdma_create_qp(ctx->id, ctx->id->pd, &attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_create_qp");
    return rc;
  }
  ctx->max_wr = MIN(ctx->max_wr, attr.cap.max_send_wr);
  ctx->wc = g_new(struct ibv_wc, ctx->max_wr);

  /* reserve and register memory for signal_msg instances */
  ctx->signal_msg_pool =
    vys_buffer_pool_new(
      SIGNAL_MSG_BLOCK_LENGTH,
      SIZEOF_VYS_SIGNAL_MSG(ctx->signal_msg_num_spectra));
  ctx->mr = rdma_reg_msgs(
    ctx->id, ctx->signal_msg_pool->pool, ctx->signal_msg_pool->pool_size);
  if (G_UNLIKELY(ctx->mr == NULL)) {
    VERB_ERR(error_record, errno, "rdma_reg_msgs");
    return -1;
  }

  ctx->num_not_ack = 0;
  ctx->min_ack = SIGNAL_MSG_QUEUE_LENGTH;
  return 0;
}

static int
init_multicast(struct vyssim_context *vyssim,
               struct vys_error_record **error_record)
{
  int result = -1;
  struct mcast_context *ctx = &(vyssim->mcast_ctx);

  ctx->event_channel = rdma_create_event_channel();
  if (G_UNLIKELY(ctx->event_channel == NULL)) {
    VERB_ERR(error_record, errno, "rdma_create_event_channel");
    return result;
  }

  int rc = rdma_create_id(ctx->event_channel, &ctx->id, ctx, RDMA_PS_UDP);
  if (G_UNLIKELY(rc != 0)) {
    ctx->id = NULL;
    VERB_ERR(error_record, errno, "rdma_create_id failed");
    return rc;
  }

  rc = resolve_addr(vyssim, error_record);
  if (G_UNLIKELY(rc != 0))
    return rc;

  /* get MTU */
  struct ibv_port_attr port_attr;
  rc = ibv_query_port(ctx->id->verbs, ctx->id->port_num, &port_attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_query_port");
    return rc;
  }
  int mtu = 1 << (port_attr.active_mtu + 7);
  /* Verify that the message size is not larger than the MTU */
  if (SIZEOF_VYS_SIGNAL_MSG(ctx->signal_msg_num_spectra) > mtu) {
    MSG_ERROR(error_record, -1,
              "message size %lu is larger then active mtu %d",
              SIZEOF_VYS_SIGNAL_MSG(ctx->signal_msg_num_spectra),
              mtu);
    return result;
  }

  ctx->comp_channel = ibv_create_comp_channel(ctx->id->verbs);
  if (G_UNLIKELY(ctx->comp_channel == NULL)) {
    VERB_ERR(error_record, errno, "ibv_create_comp_channel");
    return result;
  }

  ctx->num_wr = 0;
  ctx->max_wr = SIGNAL_MSG_MAX_POSTED;

  struct ibv_device_attr dev_attr;
  rc = ibv_query_device(ctx->id->verbs, &dev_attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_query_device");
    return rc;
  }
  ctx->max_wr = MIN(ctx->max_wr, dev_attr.max_cq);

  rc = create_mcast_resources(ctx, error_record);
  if (G_UNLIKELY(rc != 0))
    return rc;

  /* join multicast group */
  rc = rdma_join_multicast(ctx->id, &ctx->sockaddr, NULL);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_join_multicast");
    return rc;
  }

  /* verify that we joined multicast group */
  struct rdma_cm_event *event;
  rc = get_cm_event(ctx->event_channel, RDMA_CM_EVENT_MULTICAST_JOIN,
                    &event, error_record);
  if (rc == 0) {
    ctx->remote_qpn = event->param.ud.qp_num;
    ctx->remote_qkey = event->param.ud.qkey;
    int rc1 = 0;
    ctx->ah = ibv_create_ah(ctx->id->pd, &event->param.ud.ah_attr);
    if (G_UNLIKELY(ctx->ah == NULL)) {
      rc1 = -1;
      VERB_ERR(error_record, errno, "ibv_create_ah");
    }
    rdma_ack_cm_event(event);

    if (rc == 0 && rc1 == 0)
      result = 0;
  }
  return result;
}

static unsigned
num_spectra_per_integration_per_baseline(const struct vyssim_context *vyssim)
{
  GArray *spw_descs = vyssim->spw_descriptors;
  unsigned result = 0;
  for (unsigned i = 0; i < spw_descs->len; ++i) {
    result +=
      (&g_array_index(spw_descs, struct spectral_window_descriptor, i))
      ->num_polprods_indices;
  }
  return result;
}

static int
init(struct vyssim_context *vyssim, struct vys_error_record **error_record)
{
  int rc = init_multicast(vyssim, error_record);
  if (G_UNLIKELY(rc != 0))
    return -1;

  struct server_context *ctx = &(vyssim->server_ctx);
  ctx->event_channel = rdma_create_event_channel();
  if (G_UNLIKELY(ctx->event_channel == NULL)) {
    VERB_ERR(error_record, errno, "rdma_create_event_channel");
    return -1;
  }

  rc = rdma_create_id(ctx->event_channel, &(ctx->id), vyssim, RDMA_PS_TCP);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_create_id");
    return rc;
  }

  ctx->pollfds = g_array_new(FALSE, FALSE, sizeof(struct pollfd));

  /* convert number of data buffers as time in seconds to number of spectra */
  unsigned num_spectra_per_integration =
    num_spectra_per_integration_per_baseline(vyssim) *
    NUM_BASELINES(vyssim->params.num_antennas);
  double num_integrations_per_second =
    1.0e6 / vyssim->params.integration_time_microsec;
  ctx->num_data_buffers =
    vyssim->data_buffer_length_sec *
    num_spectra_per_integration * num_integrations_per_second;
  unsigned signal_msg_usage =
    SIGNAL_MSG_BLOCK_LENGTH * vyssim->mcast_ctx.signal_msg_num_spectra;
  ctx->num_data_buffers += signal_msg_usage;

  /* allocate the memory for data buffers */
  ctx->data_buffer_block_size =
    ctx->num_data_buffers
    * (2 * vyssim->params.num_channels * sizeof(float)
       + VYS_SPECTRUM_OFFSET);
  ctx->data_buffer_block = g_malloc(ctx->data_buffer_block_size);
  ctx->data_buffer_index = 0;
  ctx->data_buffer_len =
    2 * vyssim->params.num_channels + VYS_SPECTRUM_OFFSET;

  ctx->total_size_per_signal =
    ctx->data_buffer_len * vyssim->mcast_ctx.signal_msg_num_spectra *
    sizeof(float);

  /* listen on server port for rdma connections */
  ctx->connections = NULL;
  memcpy(&(ctx->sockaddr), &(vyssim->sockaddr), sizeof(ctx->sockaddr));
  rc = rdma_bind_addr(ctx->id, &(ctx->sockaddr));
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_bind_addr");
    return rc;
  }
  vyssim->sockaddr.sin_port = rdma_get_src_port(ctx->id);
  rc = rdma_listen(ctx->id, LISTEN_BACKLOG);

  ctx->num_queued = 0;
  MUTEX_INIT(ctx->queue_mutex);
#if !GLIB_CHECK_VERSION(2,32,0)
  if (G_UNLIKELY(ctx->queue_mutex == NULL)) {
    MSG_ERROR(error_record, -1, "%s", "failed to create data queue mutex");
    return -1;
  }
#endif
  COND_INIT(ctx->queue_changed_condition);
#if !GLIB_CHECK_VERSION(2,32,0)
  if (G_UNLIKELY(ctx->queue_changed_condition == NULL)) {
    MSG_ERROR(error_record, -2, "%s",
              "failed to create data queue condition variable");
    return -1;
  }
#endif
  /* synchronize data generation clocks */
  vyssim->epoch_ms = g_get_real_time() / 1000;
  MPI_Bcast(&vyssim->epoch_ms, 1, MPI_UINT64_T, 0, vyssim->comm);

  /* start data generation thread */
  GError *err = NULL;
  ctx->gen_thread = THREAD_NEW("data_generator", (GThreadFunc)data_generator,
                               vyssim);
  if (err != NULL) {
    MSG_ERROR(error_record, -1,
              "failed to start data generation thread: %s",
              err->message);
    g_error_free(err);
    return -1;
  }
  return 0;
}

static int
start_send_timer(struct vyssim_context *vyssim, struct pollfd *pfd,
                 struct vys_error_record **error_record)
{
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (fd < 0) {
    MSG_ERROR(error_record, errno, "failed to create timer: %s",
              strerror(errno));
    return -1;
  }
  unsigned num_spectra_per_integration =
    num_spectra_per_integration_per_baseline(vyssim) *
    NUM_BASELINES(vyssim->params.num_antennas);

  double num_signals_per_integration =
    (double)num_spectra_per_integration /
    vyssim->mcast_ctx.signal_msg_num_spectra;

  unsigned long nanosec_per_signal =
    (unsigned long)((1000uL * vyssim->params.integration_time_microsec) /
                    num_signals_per_integration + 0.5);

  struct itimerspec send_timerspec = {
    .it_value = {.tv_sec = 1, .tv_nsec = 0},
    .it_interval = {.tv_sec = nanosec_per_signal / 1000000000uL,
                    .tv_nsec = nanosec_per_signal % 1000000000uL}
  };
  int rc = timerfd_settime(fd, 0, &send_timerspec, NULL);
  if (G_UNLIKELY(rc != 0)) {
    MSG_ERROR(error_record, errno, "failed to start timer: %s",
              strerror(errno));
    int rc1 = close(fd);
    if (G_UNLIKELY(rc1 != 0))
      MSG_ERROR(error_record, errno, "failed to close timer fd: %s",
                strerror(errno));
    return rc;
  }
  pfd->fd = fd;
  pfd->events = POLLIN;
  return 0;
}

static int
stop_send_timer(int fd, struct vys_error_record **error_record)
{
  struct itimerspec send_timerspec = {
    .it_value = {.tv_sec = 0, .tv_nsec = 0}
  };
  int rc = timerfd_settime(fd, 0, &send_timerspec, NULL);
  if (G_UNLIKELY(rc != 0))
    MSG_ERROR(error_record, errno, "failed to stop timer: %s",
              strerror(errno));
  int rc1 = close(fd);
  if (G_UNLIKELY(rc1 != 0))
    MSG_ERROR(error_record, errno, "failed to close timer fd: %s",
              strerror(errno));
  if (rc == 0 && rc1 != 0) rc = rc1;
  return rc;
}

static int
on_client_connect(struct server_context *server_ctx, struct rdma_cm_id *id,
                  struct rdma_conn_param *conn_param,
                  struct vys_error_record **error_record)
{
  struct ibv_qp_init_attr qp_attr;
  memset(&qp_attr, 0, sizeof(qp_attr));
  qp_attr.qp_type = IBV_QPT_RC;
  qp_attr.sq_sig_all = 1;
  qp_attr.cap.max_send_wr = 1;
  qp_attr.cap.max_recv_wr = 1;
  qp_attr.cap.max_send_sge = 1;
  qp_attr.cap.max_recv_sge = 1;
  int rc = rdma_create_qp(id, NULL, &qp_attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_create_qp");
    return rc;
  }
  struct ibv_mr *mr = rdma_reg_read(
    id, server_ctx->data_buffer_block, server_ctx->data_buffer_block_size);
  if (G_UNLIKELY(mr == NULL)) {
    VERB_ERR(error_record, errno, "rdma_reg_read");
    return errno;
  }

  struct ibv_device_attr dev_attr;
  rc = ibv_query_device(id->verbs, &dev_attr);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_query_device");
    return rc;
  }

  struct client_connection_context *conn_ctx =
    g_slice_new(struct client_connection_context);
  conn_ctx->id = id;
  conn_ctx->mr = mr;
  conn_ctx->established = false;
  conn_param->private_data = &(conn_ctx->mr->rkey);
  conn_param->private_data_len = sizeof(conn_ctx->mr->rkey);
  conn_param->initiator_depth = 0;
  conn_param->responder_resources =
    MIN(conn_param->responder_resources, dev_attr.max_qp_rd_atom);
  rc = rdma_accept(id, conn_param);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(error_record, errno, "rdma_accept");
  server_ctx->connections =
    g_slist_prepend(server_ctx->connections, conn_ctx);
  return rc;
}

static int
begin_client_disconnect(struct server_context *server_ctx,
                        GSList *connection_node,
                        struct vys_error_record **error_record)
{
  struct client_connection_context *conn_ctx = connection_node->data;
  int rc = 0;
  if (conn_ctx->established) {
    rc = rdma_disconnect(conn_ctx->id);
    if (G_UNLIKELY(rc != 0))
      VERB_ERR(error_record, errno, "rdma_disconnect");
    conn_ctx->established = false;
  }
  return rc;
}

static int
complete_client_disconnect(struct server_context *server_ctx,
                           GSList *connection_node,
                           struct vys_error_record **error_record)
{
  struct client_connection_context *conn_ctx = connection_node->data;
  server_ctx->connections =
    g_slist_delete_link(server_ctx->connections, connection_node);
  int rc = rdma_dereg_mr(conn_ctx->mr);
  if (G_UNLIKELY(rc != 0))
    VERB_ERR(error_record, errno, "rdma_dereg_mr");
  rdma_destroy_qp(conn_ctx->id);
  int rc1 = rdma_destroy_id(conn_ctx->id);
  if (G_UNLIKELY(rc1 != 0))
    VERB_ERR(error_record, errno, "rdma_destroy_id");
  g_slice_free(struct client_connection_context, conn_ctx);
  if (rc == 0 && rc1 != 0) rc = rc1;
  return rc;
}

static int
compare_client_connection_context(
  const struct client_connection_context *ctx, const struct rdma_cm_id *id)
{
  if (ctx->id == id) return 0;
  return 1;
}

static int
on_cm_event(struct server_context *server_ctx,
            struct vys_error_record **error_record)
{
  struct rdma_cm_event *event = NULL;
  int rc = rdma_get_cm_event(server_ctx->event_channel, &event);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "rdma_get_cm_event");
    return -1;
  }
  switch (event->event) {
  case RDMA_CM_EVENT_CONNECT_REQUEST: {
    rc = on_client_connect(server_ctx, event->id, &(event->param.conn),
                           error_record);
    int rc1 = rdma_ack_cm_event(event);
    if (rc1 != 0) {
      VERB_ERR(error_record, errno, "rdma_ack_cm_event");
      if (rc == 0) rc = rc1;
    }
    break;
  }
  case RDMA_CM_EVENT_ESTABLISHED: {
    GSList *conn_ctx_node =
      g_slist_find_custom(server_ctx->connections, event->id,
                          (GCompareFunc)compare_client_connection_context);
    rc = rdma_ack_cm_event(event);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "rdma_ack_cm_event");
      return rc;
    }
    if (G_UNLIKELY(conn_ctx_node == NULL)) {
      MSG_ERROR(
        error_record, -1,
        "failed to find connection for RDMA_CM_EVENT_ESTABLISHED");
      return -1;
    }
    struct client_connection_context *conn_ctx = conn_ctx_node->data;
    conn_ctx->established = true;
    break;
  }
  case RDMA_CM_EVENT_DISCONNECTED: {
    GSList *conn_ctx_node =
      g_slist_find_custom(server_ctx->connections, event->id,
                          (GCompareFunc)compare_client_connection_context);
    rc = rdma_ack_cm_event(event);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "rdma_ack_cm_event");
      return rc;
    }
    if (G_UNLIKELY(conn_ctx_node == NULL)) {
      MSG_ERROR(
        error_record, -1,
        "failed to find connection for RDMA_CM_EVENT_DISCONNECTED");
      return -1;
    }
    rc = begin_client_disconnect(server_ctx, conn_ctx_node, error_record);
    if (rc == 0)
      rc = complete_client_disconnect(server_ctx, conn_ctx_node,
                                      error_record);
    break;
  }
  default:
    break;
  }
  return rc;
}

static int
on_mc_event(struct mcast_context *ctx,
            struct vys_error_record **error_record)
{
  struct ibv_cq *ev_cq;
  void *ev_ctx;
  int rc = ibv_get_cq_event(ctx->comp_channel, &ev_cq, &ev_ctx);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, errno, "ibv_get_cq_event");
    return rc;
  }

  ctx->num_not_ack++;
  if (ctx->num_not_ack >= ctx->min_ack) {
    ibv_ack_cq_events(ev_cq, ctx->num_not_ack);
    ctx->num_not_ack = 0;
  }

  rc = ibv_req_notify_cq(ev_cq, 0);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_req_notify_cq");
    return rc;
  }

  int nc = ibv_poll_cq(ev_cq, ctx->num_wr, ctx->wc);
  if (nc < 0) {
    VERB_ERR(error_record, errno, "ibv_poll_cq");
    return -1;
  } else if (nc > 0) {
    g_assert(ctx->num_wr >= nc);
    ctx->num_wr -= nc;
    for (int i = 0; i < nc; ++i) {
      struct vys_signal_msg *msg =
        (struct vys_signal_msg *)ctx->wc[i].wr_id;
      free_signal_msg(ctx, msg);
      // TODO: check (ctx->wc[i].status == IBV_WC_SUCCESS) ?
    }
  }
  return 0;
}

static int
handle_timer_event(struct vyssim_context *vyssim, uint64_t *num_events,
                   struct vys_error_record **error_record)
{
  /* num_events points to the number of events the caller wishes to handle;
   * its value upon return is its initial value less the number of work
   * requests posted
   */
  struct mcast_context *ctx = &(vyssim->mcast_ctx);

  static struct ibv_sge *sges = NULL;
  if (G_UNLIKELY(sges == NULL)) sges = g_new0(struct ibv_sge, ctx->max_wr);
  static struct ibv_send_wr *wrs = NULL;
  if (G_UNLIKELY(wrs == NULL)) wrs = g_new0(struct ibv_send_wr, ctx->max_wr);

  unsigned num_wr = ctx->max_wr - ctx->num_wr;
  num_wr = MIN(num_wr, *num_events);
  for (unsigned i = 0; i < num_wr; ++i) {
    struct vys_signal_msg *msg = pop_msg_from_queue(vyssim);

    struct ibv_sge *sge = &sges[i];
    sge->length =
      SIZEOF_VYS_SIGNAL_MSG_PAYLOAD(ctx->signal_msg_num_spectra);
    sge->lkey = ctx->mr->lkey;
    sge->addr = (uint64_t)&(msg->payload);

    /* Multicast requires that the message is sent with immediate data
     * and that the QP number is the contents of the immediate data */
    struct ibv_send_wr *wr = &wrs[i];
    wr->next = &wrs[i + 1];
    wr->sg_list = sge;
    wr->num_sge = 1;
    wr->opcode = IBV_WR_SEND_WITH_IMM;
    wr->send_flags = IBV_SEND_SIGNALED;
    wr->imm_data = htonl(ctx->id->qp->qp_num);
    wr->wr.ud.ah = ctx->ah;
    wr->wr.ud.remote_qpn = ctx->remote_qpn;
    wr->wr.ud.remote_qkey = ctx->remote_qkey;
    wr->wr_id = (uint64_t)msg;
  }

  int rc = ibv_req_notify_cq(ctx->cq, 0);
  if (G_UNLIKELY(rc != 0)) {
    VERB_ERR(error_record, rc, "ibv_req_notify_cq");
    return rc;
  }

  if (num_wr > 0) {
    wrs[num_wr - 1].next = NULL;

    struct ibv_send_wr *bad_wr;
    rc = ibv_post_send(ctx->id->qp, wrs, &bad_wr);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, rc, "ibv_post_send");
      return rc;
    }

    ctx->num_wr += num_wr;
    *num_events -= num_wr;
  }

  return 0;
}

static int
on_timer_event(struct vyssim_context *vyssim,
               struct vys_error_record **error_record,
               int timerfd, uint64_t *backlog)
{
  uint64_t n;
  int rc = read(timerfd, &n, sizeof(n));
  if (rc >= 0) {
    *backlog += n;
    rc = handle_timer_event(vyssim, backlog, error_record);
  } else {
    MSG_ERROR(error_record, errno, "failed to read timerfd: %s",
              strerror(errno));
  }
  return rc;
}

static int
send_msgs(struct vyssim_context *vyssim, struct vys_error_record **error_record)
{
  struct mcast_context *mcast_ctx = &(vyssim->mcast_ctx);
  struct server_context *server_ctx = &(vyssim->server_ctx);

  int rc;
  g_array_set_size(server_ctx->pollfds, NUM_EVENT_FDS);
  struct pollfd pfd;

  /* rdma cm event channel */
  rc = set_nonblocking(server_ctx->event_channel->fd);
  if (G_UNLIKELY(rc != 0)) {
    MSG_ERROR(error_record, errno,
              "failed to set rdma cm event channel to non-blocking: %s",
              strerror(errno));
    return rc;
  }
  pfd.fd = server_ctx->event_channel->fd;
  pfd.events = POLLIN;
  g_array_index(server_ctx->pollfds, struct pollfd, CM_EVENT_FD) = pfd;

  /* multicast completion channel */
  rc = set_nonblocking(mcast_ctx->comp_channel->fd);
  if (G_UNLIKELY(rc != 0)) {
    MSG_ERROR(
      error_record, errno,
      "failed to set multicast completion channel to non-blocking: %s",
      strerror(errno));
    return rc;
  }
  pfd.fd = mcast_ctx->comp_channel->fd;
  pfd.events = POLLIN;
  g_array_index(
    server_ctx->pollfds, struct pollfd, MULTICAST_EVENT_FD) = pfd;

  /* create timer to generate events periodically */
  start_send_timer(
    vyssim,
    &g_array_index(server_ctx->pollfds, struct pollfd, TIMER_EVENT_FD),
    error_record);

  /* main loop */
  uint64_t timer_event_backlog = 0;
  bool quitting = false;
  bool quit = false;
  while (!quit) {
    int nfd = poll((struct pollfd *)server_ctx->pollfds->data,
                   server_ctx->pollfds->len, -1);
    if (nfd > 0) {
      for (int j = 0; rc == 0 && j < server_ctx->pollfds->len; ++j) {
        struct pollfd *pfd =
          &(g_array_index(server_ctx->pollfds, struct pollfd, j));
        if (pfd->revents & POLLIN) {
          switch (j) {
          case CM_EVENT_FD:
            rc = on_cm_event(server_ctx, error_record);
            break;
          case MULTICAST_EVENT_FD:
            rc = on_mc_event(mcast_ctx, error_record);
            break;
          case TIMER_EVENT_FD:
            rc = on_timer_event(vyssim, error_record, pfd->fd,
                                &timer_event_backlog);
            break;
          default:
            break;
          }
        } else if (pfd->revents & (POLLERR | POLLHUP)) {
          MSG_ERROR(error_record, -1, "poll returned error or hup");
          rc = -1;
        }
      }
    } else if (nfd < 0) {
      MSG_ERROR(error_record, errno, "poll failed: %s", strerror(errno));
      quitting = true;
      /* rc = server_disconnect(server_ctx, errmsg); */
      if (rc == 0) {
        rc = stop_send_timer(
          (&g_array_index(server_ctx->pollfds, struct pollfd,
                          TIMER_EVENT_FD))->fd,
          error_record);
        g_array_remove_index(server_ctx->pollfds, TIMER_EVENT_FD);
      }
    }

    if (quitting && server_ctx->connections == NULL
        && mcast_ctx->num_wr == 0)
      quit = true;

    if (rc < 0) quit = true;
  }
  return rc;
}

static void
ack_and_drain_cq(unsigned num_to_ack, unsigned num_wr, struct ibv_cq *cq)
{
  if (num_to_ack > 0)
    ibv_ack_cq_events(cq, num_to_ack);

  if (num_wr > 0) {
    struct ibv_wc *wc = g_newa(struct ibv_wc, num_wr);
    while (num_wr > 0){
      int nc = ibv_poll_cq(cq, num_wr, wc);
      num_wr -= nc;
    }
  }
}

static int
destroy_mcast_resources(struct mcast_context *ctx,
                        struct vys_error_record **error_record)
{
  int rc;
  int result = EXIT_SUCCESS;

  if (ctx->ah != NULL) {
    rc = ibv_destroy_ah(ctx->ah);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "ibv_destroy_ah");
      result = EXIT_FAILURE;
    }
  }
  if (ctx->id != NULL && ctx->id->qp != NULL)
    rdma_destroy_qp(ctx->id);
  if (ctx->cq != NULL) {
    ack_and_drain_cq(ctx->num_not_ack, ctx->num_wr, ctx->cq);

    rc = ibv_destroy_cq(ctx->cq);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "ibv_destroy_cq");
      result = EXIT_FAILURE;
    }
  }
  if (ctx->mr != NULL) {
    rc = rdma_dereg_mr(ctx->mr);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "rdma_dereg_mr");
      result = EXIT_FAILURE;
    }
  }
  if (ctx->comp_channel != NULL)
    ibv_destroy_comp_channel(ctx->comp_channel);

  if (ctx->signal_msg_pool != NULL)
    vys_buffer_pool_free(ctx->signal_msg_pool);
  if (ctx->id != NULL) {
    rc = rdma_destroy_id(ctx->id);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "rdma_destroy_id");
      result = EXIT_FAILURE;
    }
  }
  if (ctx->wc != NULL)
    g_free(ctx->wc);
  return result;
}

static int
fin_multicast(struct vyssim_context *vyssim,
              struct vys_error_record **error_record)
{
  struct mcast_context *ctx = &(vyssim->mcast_ctx);
  int result = 0;
  int rc;

  if (ctx->id != NULL) {
    rc = rdma_leave_multicast(ctx->id, &ctx->sockaddr);
    if (G_UNLIKELY(rc != 0)) {
      VERB_ERR(error_record, errno, "rdma_leave_multicast");
      result = rc;
    }
  }
  rc = destroy_mcast_resources(ctx, error_record);
  if (G_UNLIKELY(rc != 0))
    result = -1;
  if (ctx->event_channel != NULL)
    rdma_destroy_event_channel(ctx->event_channel);

  return result;
}

static int
fin(struct vyssim_context *vyssim, struct vys_error_record **error_record)
{
  struct server_context *ctx = &(vyssim->server_ctx);

  /* drain queue, then set signal_msg_num_spectra to zero to signal data
   * generation thread should exit */
  MUTEX_LOCK(ctx->queue_mutex);
  ctx->num_queued = 0;
  vyssim->mcast_ctx.signal_msg_num_spectra = 0;
  COND_SIGNAL(ctx->queue_changed_condition);
  MUTEX_UNLOCK(ctx->queue_mutex);

  /* join data generation thread, clean up its resources -- make sure to clean
   * up data queue once again */
  if (ctx->gen_thread != NULL)
    g_thread_join(ctx->gen_thread);

  COND_CLEAR(ctx->queue_changed_condition);
  MUTEX_CLEAR(ctx->queue_mutex);

  if (ctx->data_buffer_block != NULL)
    g_free(ctx->data_buffer_block);

  /* clean up rdma resources */
  if (ctx->comp_channel != NULL)
    ibv_destroy_comp_channel(ctx->comp_channel);

  int rc = 0;

  if (ctx->id != NULL) {
    rc = rdma_destroy_id(ctx->id);
    if (G_UNLIKELY(rc != 0))
      VERB_ERR(error_record, errno, "rdma_destroy_id");
  }

  if (ctx->event_channel != NULL)
    rdma_destroy_event_channel(ctx->event_channel);

  if (ctx->pollfds != NULL)
    g_array_free(ctx->pollfds, TRUE);

  int rc1 = fin_multicast(vyssim, error_record);

  if (rc == 0 && rc1 != 0) rc = rc1;
  return rc;
}

static int
run(struct vyssim_context *vyssim)
{
  struct vys_error_record *error_record = NULL;
  int rc = init(vyssim, &error_record);
  if (rc == 0)
    rc = send_msgs(vyssim, &error_record);
  fin(vyssim, &error_record);
  if (error_record != NULL) {
    rc = -1;
    char *errs = vys_error_record_to_string(&error_record);
    fprintf(stderr, "vyssim failed:\n%s", errs);
    g_free(errs);
    vys_error_record_free(error_record);
  } else {
    rc = 0;
  }
  return rc;
}

static gboolean
parse_param(const gchar *option_name, const gchar *value, GHashTable *params,
            GError **error)
{
  const gchar *opt = option_name;
  while (*opt == '-') ++opt;
  char *end = NULL;
  errno = 0;
  glong l = strtol(value, &end, 0);
  if (*end != '\0' || errno == EINVAL) {
    g_set_error(error, VYSSIM_ARG_ERROR, VYSSIM_ARG_ERROR_PARSE,
                "Failed to parse %s value: %s", value, strerror(EINVAL));
    return false;
  }
  if (strcmp(opt, num_polprods_lname) == 0
      || strcmp(opt, num_polprods_sname) == 0) {
    if (!(l == 1 || l == 2 || l == 4)) {
      g_set_error(error, VYSSIM_ARG_ERROR, VYSSIM_ARG_ERROR_RANGE,
                  "%s value must be 1, 2, or 4", option_name);
      return false;
    }
  } else if (l <= 0) {
    g_set_error(error, VYSSIM_ARG_ERROR, VYSSIM_ARG_ERROR_RANGE,
                "%s value must be positive", option_name);
    return false;
  } else if (l > G_MAXUINT) {
    g_set_error(error, VYSSIM_ARG_ERROR, VYSSIM_ARG_ERROR_RANGE,
                "%s value must not exceed %u", option_name,
                G_MAXUINT);
    return false;
  }
  param_set_unsigned(params, opt, (guint)l);
  return true;
}

gchar *
add_param(GHashTable *params, const gchar *lname, const gchar *sname,
          guint value, const gchar *desc, unsigned *where)
{
  g_hash_table_insert(params, (gchar *)lname, where);
  g_hash_table_insert(params, (gchar *)sname, where);
  *where = value;
  return g_strdup_printf("%s [default: %u]", desc, value);
}

static bool
parse_options(int *argc, char **argv[], unsigned *num_antennas,
              unsigned *num_spectral_windows, unsigned *num_channels,
              unsigned *num_polprods, unsigned *integration_time_microsec,
              unsigned *signal_msg_num_spectra,
              unsigned *data_buffer_length_sec,
              char **vys_configuration_path,
              GError **error)
{
  GOptionContext *context = g_option_context_new(NULL);
  g_option_context_set_summary(context, summary);
  g_option_context_set_description(
    context,
    "Please contact <mpokorny@nrao.edu> for praise, curses, etc.");
  g_option_context_set_help_enabled(context, true);
  g_option_context_set_ignore_unknown_options(context, false);

  GHashTable *params = g_hash_table_new(g_str_hash, g_str_equal);
  GOptionGroup *main_group =
    g_option_group_new("", "", "", params,
                       (GDestroyNotify)g_hash_table_destroy);
  gchar *num_antennas_desc =
    add_param(
      params, num_antennas_lname, num_antennas_sname,
      DEFAULT_NUM_ANTENNAS, "Number of antennas",
      num_antennas);
  gchar *num_spectral_windows_desc =
    add_param(
      params, num_spectral_windows_lname, num_spectral_windows_sname,
      DEFAULT_NUM_SPECTRAL_WINDOWS, "Number of spectral windows",
      num_spectral_windows);
  gchar *num_channels_desc =
    add_param(
      params, num_channels_lname, num_channels_sname,
      DEFAULT_NUM_CHANNELS, "Number of channels (per spw)",
      num_channels);
  gchar *num_polprods_desc =
    add_param(
      params, num_polprods_lname, num_polprods_sname,
      DEFAULT_NUM_POLPRODS, "Number of polarization products (per spw)",
      num_polprods);
  gchar *integration_time_microsec_desc =
    add_param(
      params, integration_time_microsec_lname,
      integration_time_microsec_sname,
      DEFAULT_INTEGRATION_TIME_MICROSEC,
      "Integration time (microseconds)", integration_time_microsec);
  gchar *signal_msg_num_spectra_desc =
    add_param(
      params, signal_msg_num_spectra_lname, signal_msg_num_spectra_sname,
      DEFAULT_SIGNAL_MSG_NUM_SPECTRA,
      "Number of spectra per signal message", signal_msg_num_spectra);
  gchar *data_buffer_length_sec_desc =
    add_param(
      params, data_buffer_length_sec_lname, data_buffer_length_sec_sname,
      DEFAULT_DATA_BUFFER_LENGTH_SEC, "Data buffer length (seconds)",
      data_buffer_length_sec);
  *vys_configuration_path = NULL;
  GOptionEntry entries[] = {
    {num_antennas_lname, num_antennas_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     num_antennas_desc, "N"},
    {num_spectral_windows_lname, num_spectral_windows_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     num_spectral_windows_desc, "N"},
    {num_channels_lname, num_channels_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     num_channels_desc, "N"},
    {num_polprods_lname, num_polprods_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     num_polprods_desc, "N"},
    {integration_time_microsec_lname, integration_time_microsec_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     integration_time_microsec_desc, "N"},
    {signal_msg_num_spectra_lname, signal_msg_num_spectra_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     signal_msg_num_spectra_desc, "N"},
    {data_buffer_length_sec_lname, data_buffer_length_sec_sname[0], 0,
     G_OPTION_ARG_CALLBACK, parse_param,
     data_buffer_length_sec_desc, "N"},
    {vys_configuration_path_lname, vys_configuration_path_sname[0], 0,
     G_OPTION_ARG_FILENAME, vys_configuration_path,
     "vys configuration file path", "PATH"},
    {NULL}
  };
  g_option_group_add_entries(main_group, entries);
  g_option_context_set_main_group(context, main_group);

  bool result = g_option_context_parse(context, argc, argv, error);
  g_free(num_antennas_desc);
  g_free(num_spectral_windows_desc);
  g_free(num_channels_desc);
  g_free(num_polprods_desc);
  g_free(integration_time_microsec_desc);
  g_free(signal_msg_num_spectra_desc);
  g_free(data_buffer_length_sec_desc);
  g_option_context_free(context);
  return result;
}

int
main(int argc, char *argv[])
{
  struct vyssim_context vyssim;
  memset(&vyssim, 0, sizeof(vyssim));
  setlocale(LC_ALL, "");

  int rc = EXIT_FAILURE;
  GError *error = NULL;
  char *vys_configuration_path;
  if (!parse_options(&argc, &argv,
                     &vyssim.params.num_antennas,
                     &vyssim.params.num_spectral_windows,
                     &vyssim.params.num_channels,
                     &vyssim.params.num_polprods,
                     &vyssim.params.integration_time_microsec,
                     &vyssim.mcast_ctx.signal_msg_num_spectra,
                     &vyssim.data_buffer_length_sec,
                     &vys_configuration_path,
                     &error)) {
    g_print("option parsing failed: %s\n", error->message);
    g_error_free(error);
    goto cleanup_and_return;
  }

  vyssim.bind_addr = vys_get_ipoib_addr();
  if (vyssim.bind_addr == NULL) {
    fprintf(stderr, "unable to determine IP address of IPOIB interface\n");
    goto cleanup_and_return;
  }
  inet_pton(AF_INET, vyssim.bind_addr, &(vyssim.sockaddr.sin_addr));
  vyssim.sockaddr.sin_family = AF_INET;
  vyssim.sockaddr.sin_port = 0;

  THREAD_INIT;

  // TODO: verify MPI thread level
  int provided;
  MPI_Init_thread(&argc, &argv, MPI_THREAD_FUNNELED, &provided);
  if (provided < MPI_THREAD_FUNNELED) {
    fprintf(stderr, "unable to support MPI_THREAD_FUNNELED\n");
    goto cleanup_and_return;
  }

  vyssim.comm = MPI_COMM_WORLD;
  int rank;
  MPI_Comm_rank(vyssim.comm, &rank);
  int num_servers;
  MPI_Comm_size(vyssim.comm, &num_servers);

  /* distribute products among all servers */
  unsigned polprod_group_size =
    (vyssim.params.num_spectral_windows * vyssim.params.num_polprods)
    / num_servers;// min number of products per server
  if (polprod_group_size == 0) {
    fprintf(stderr,
            "require reduced number of servers (no more than %u for "
            "provided configuration)\n",
            vyssim.params.num_spectral_windows *
            vyssim.params.num_polprods);
    goto cleanup_and_return;
  }
  /* min power of two products per server*/
  polprod_group_size =
    1 << g_bit_nth_msf(polprod_group_size, 8 * sizeof(unsigned));
  /* distribute by no more than num_polprods products at a time */
  polprod_group_size = MIN(polprod_group_size, vyssim.params.num_polprods);
  /* number of groups a spectral window's polarization products are divided
   * into */
  unsigned num_polprod_groups =
    vyssim.params.num_polprods / polprod_group_size;
  /* total number of groups of polprods products to distribute  */
  unsigned num_groups =
    vyssim.params.num_spectral_windows * num_polprod_groups;
  /* distribute groups (spectral window plus a number of polprods products) in
   * round-robin order to all processes (servers) */
  vyssim.spw_descriptors = g_array_new(
    FALSE, FALSE, sizeof(struct spectral_window_descriptor));
  for (unsigned grp = rank; grp < num_groups; grp += num_servers) {
    unsigned polprod_group = grp % num_polprod_groups;
    struct spectral_window_descriptor spw_desc = {
      .index = grp / num_polprod_groups,
      .num_polprods_indices = polprod_group_size
    };
    for (unsigned p = 0; p < polprod_group_size; ++p)
      spw_desc.polprods_indices[p] = polprod_group * polprod_group_size + p;
    g_array_append_val(vyssim.spw_descriptors, spw_desc);
  }

  if (rank == 0)
    g_print("Starting vyssim using %u process%s\n"
            "with %u antennas, %u spectral windows of %u channels and\n"
            "%u polarization products each, distributed %u way%s,\n"
            "integration time of %u microseconds,\n"
            "%u spectra per signal message, spectra retained for %u seconds\n",
            num_servers, ((num_servers > 1) ? "es" : ""),
            vyssim.params.num_antennas, vyssim.params.num_spectral_windows,
            vyssim.params.num_channels,
            vyssim.params.num_polprods, num_polprod_groups,
            ((num_polprod_groups > 1) ? "s" : ""),
            vyssim.params.integration_time_microsec,
            vyssim.mcast_ctx.signal_msg_num_spectra,
            vyssim.data_buffer_length_sec);

  vyssim.vconfig = vys_configuration_new(vys_configuration_path);

  rc = run(&vyssim);
  if (rc == 0) rc = EXIT_SUCCESS;
  else rc = EXIT_FAILURE;

cleanup_and_return:
  if (vyssim.vconfig != NULL)
    vys_configuration_free(vyssim.vconfig);
  if (vyssim.spw_descriptors != NULL)
    g_array_free(vyssim.spw_descriptors, TRUE);
  if (vyssim.bind_addr != NULL)
    g_free(vyssim.bind_addr);
  int flag;
  MPI_Initialized(&flag);
  if (flag != 0) MPI_Finalize();
  return 0;
}

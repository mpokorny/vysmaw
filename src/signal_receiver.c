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
#include <vysmaw.h>
#include <signal_receiver.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <glib.h>

#define SHUTDOWN_TIMER_FD_INDEX 0
#define RECEIVE_COMPLETION_FD_INDEX 1
#define LOOP_FD_INDEX 2
#define NUM_FDS 3

enum run_state {
	STATE_INIT,
	STATE_RUN,
	STATE_QUIT,
	STATE_DONE
};

struct signal_receiver_context_ {
	struct signal_receiver_context *shared;
	struct pollfd pollfds[NUM_FDS];
	enum run_state state;
	struct data_path_message *end_msg;
	struct sockaddr sockaddr;
	struct rdma_event_channel *event_channel;
	struct rdma_cm_id *id;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;
	struct ibv_wc *wcs;
	struct ibv_mr *mr;
	bool in_multicast;
	bool in_underflow;
	uint32_t remote_qpn;
	uint32_t remote_qkey;
	unsigned num_posted_wr;
	unsigned max_posted_wr;
	unsigned min_posted_wr;
	unsigned min_ack;
	unsigned num_not_ack;
	struct recv_wr *rem_wrs;
	unsigned len_rem_wrs;
};

struct recv_wr {
	/* ibv_recv_wr element must remain the first element in this struct */
	struct ibv_recv_wr ibv_recv_wr;
	struct ibv_sge ibv_sge;
};

static struct recv_wr *recv_wr_new(
	uint64_t addr, uint32_t length, uint32_t lkey)
	__attribute__((returns_nonnull,malloc));
static struct recv_wr *recv_wr_prepend_new(
	struct recv_wr *wrs, uint64_t addr, uint32_t length, uint32_t lkey)
	__attribute__((returns_nonnull,malloc));
static void recv_wr_free(struct recv_wr *wrs);
static struct recv_wr *recv_wr_next(struct recv_wr *wr)
	__attribute__((nonnull));
static int get_cm_event(
	struct rdma_event_channel *channel, enum rdma_cm_event_type type,
	struct rdma_cm_event **out_ev, struct vys_error_record **error_record)
	__attribute__((nonnull(1)));
static int resolve_addr(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int start_signal_receive(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int stop_signal_receive(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static bool new_wr(
	struct signal_receiver_context_ *context, struct recv_wr **wrs)
	__attribute__((nonnull));
static void ack_completions(
	struct signal_receiver_context_ *context, unsigned min_ack)
	__attribute__((nonnull));
static int poll_completions(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static unsigned create_new_wrs(struct signal_receiver_context_ *context)
	__attribute__((nonnull));
static int post_wrs(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int on_poll_events(
	struct signal_receiver_context_ *context,
	struct vys_error_record**error_record)
	__attribute__((nonnull));
static int signal_receiver_loop(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int on_receive_completion(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int to_quit_state(struct signal_receiver_context_ *context,
                         struct data_path_message *msg,
                         struct vys_error_record **error_record)
	__attribute__((nonnull(1)));
static int on_loop_input(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int on_shutdown_timer_event(
	struct signal_receiver_context_ *context,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int start_shutdown_timer(
	struct pollfd *pollfd, unsigned interval_ms,
	struct vys_error_record **error_record)
	__attribute__((nonnull));
static int stop_shutdown_timer(
	struct pollfd *pollfd, struct vys_error_record **error_record)
	__attribute__((nonnull));

static struct recv_wr *
recv_wr_new(uint64_t addr, uint32_t length, uint32_t lkey)
{
	struct recv_wr *result = g_slice_new(struct recv_wr);
	result->ibv_recv_wr.sg_list = &result->ibv_sge;
	result->ibv_recv_wr.num_sge = 1;
	result->ibv_recv_wr.next = NULL;
	result->ibv_recv_wr.wr_id = addr;
	result->ibv_sge.addr = addr;
	result->ibv_sge.length = length;
	result->ibv_sge.lkey = lkey;
	return result;
}

static struct recv_wr *
recv_wr_prepend_new(struct recv_wr *wrs, uint64_t addr, uint32_t length,
                    uint32_t lkey)
{
	struct recv_wr *result = recv_wr_new(addr, length, lkey);
	result->ibv_recv_wr.next = &wrs->ibv_recv_wr;
	return result;
}

static void
recv_wr_free(struct recv_wr *wrs)
{
	g_slice_free_chain_with_offset(
		sizeof(struct recv_wr), wrs, offsetof(struct ibv_recv_wr, next));
}

static struct recv_wr *
recv_wr_next(struct recv_wr *wr)
{
	return (struct recv_wr *)wr->ibv_recv_wr.next;
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
		MSG_ERROR(error_record, errno, "rdma_get_cm_event (%s): %s",
		          rdma_event_str(type), strerror(errno));
		return rc;
	}

	/* Verify the event is the expected type */
	if (G_UNLIKELY(event->event != type)) {
		MSG_ERROR(error_record, -event->status,
		          "event: %s, expecting: %s, status: %s",
		          rdma_event_str(event->event), rdma_event_str(type),
		          strerror(-event->status));
		return -1;
	}

	/* Pass the event back to the user if requested */
	if (out_ev == NULL)
		rdma_ack_cm_event(event);
	else
		*out_ev = event;

	return 0;
}

static int
resolve_addr(struct signal_receiver_context_ *context,
             struct vys_error_record **error_record)
{
	int rc;
	struct rdma_addrinfo *mcast_rai = NULL;

	char *bind_addr = vys_get_ipoib_addr();
	if (G_UNLIKELY(bind_addr == NULL)) {
		MSG_ERROR(error_record, errno, "Failed to get IPOIB address: %s",
		          strerror(errno));
		rc = -1;
		goto resolve_addr_cleanup_and_return;
	}

	struct rdma_addrinfo hints;
	memset(&hints, 0, sizeof (hints));

	struct rdma_addrinfo *bind_rai = NULL;
	hints.ai_port_space = RDMA_PS_UDP;
	hints.ai_flags = RAI_PASSIVE;
	rc = rdma_getaddrinfo(bind_addr, NULL, &hints, &bind_rai);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_getaddrinfo (bind)");
		goto resolve_addr_cleanup_and_return;
	}

	/* bind to a specific adapter if requested to do so */
	rc = rdma_bind_addr(context->id, bind_rai->ai_src_addr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_bind_addr");
		goto resolve_addr_cleanup_and_return;
	}

	hints.ai_flags = 0;
	rc = rdma_getaddrinfo(
		(char *)context->shared->handle->config.signal_multicast_address, NULL,
		&hints, &mcast_rai);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_getaddrinfo (mcast)");
		goto resolve_addr_cleanup_and_return;
	}

	rc = rdma_resolve_addr(
		context->id, bind_rai->ai_src_addr, mcast_rai->ai_dst_addr,
		context->shared->handle->config.resolve_addr_timeout_ms);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_resolve_addr");
		goto resolve_addr_cleanup_and_return;
	}

	rc = get_cm_event(
		context->event_channel, RDMA_CM_EVENT_ADDR_RESOLVED, NULL,
		error_record);
	if (G_UNLIKELY(rc != 0))
		goto resolve_addr_cleanup_and_return;

	memcpy(&context->sockaddr, mcast_rai->ai_dst_addr, sizeof(struct sockaddr));

resolve_addr_cleanup_and_return:
	if (bind_addr != NULL)
		g_free(bind_addr);
	return rc;
}

static int
start_signal_receive(struct signal_receiver_context_ *context,
                     struct vys_error_record **error_record)
{
	/* event channel */
	context->event_channel = rdma_create_event_channel();
	if (G_UNLIKELY(context->event_channel == NULL)) {
		VERB_ERR(error_record, errno, "rdma_create_event_channel");
		return -1;
	}

	/* rdma id */
	int rc = rdma_create_id(
		context->event_channel, &context->id, context, RDMA_PS_UDP);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_create_id");
		return -1;
	}

	/* resolve my and multicast addresses */
	rc = resolve_addr(context, error_record);
	if (G_UNLIKELY(rc != 0))
		return -1;

	/* config pointer for convenience */
	const struct vysmaw_configuration *config =
		&context->shared->handle->config;

	/* set posted wr limits */
	struct ibv_device_attr dev_attr;
	rc = ibv_query_device(context->id->verbs, &dev_attr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, rc, "ibv_query_device");
		return -1;
	}
	context->max_posted_wr =
		MIN(dev_attr.max_qp_wr, config->signal_message_receive_max_posted);
	context->min_posted_wr =
		MIN(context->max_posted_wr, config->signal_message_receive_min_posted);
	/* No sense setting max_posted_wr above total number of signal buffers
	 * available. This limit is preliminary, and may be reduced further
	 * below. */
	gsize num_signal_msg_buffers =
		context->min_posted_wr * config->signal_message_pool_overhead_factor;
	context->max_posted_wr =
		MIN(context->max_posted_wr, num_signal_msg_buffers);

	context->num_posted_wr = 0;
	context->num_not_ack = 0;

	/* completion channel */
	context->comp_channel = ibv_create_comp_channel(context->id->verbs);
	if (G_UNLIKELY(context->comp_channel == NULL)) {
		VERB_ERR(error_record, errno, "ibv_create_comp_channel");
		return -1;
	}

	/* completion queue */
	context->cq = ibv_create_cq(context->id->verbs, context->max_posted_wr,
	                            NULL, context->comp_channel, 0);
	if (G_UNLIKELY(context->cq == NULL)) {
		VERB_ERR(error_record, errno, "ibv_create_cq");
		return -1;
	}

	/* queue pair */
	struct ibv_qp_init_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.qp_type = IBV_QPT_UD;
	attr.send_cq = context->cq;
	attr.recv_cq = context->cq;
	attr.sq_sig_all = 1;
	attr.cap.max_send_wr = 1;
	attr.cap.max_recv_wr = context->max_posted_wr;
	attr.cap.max_send_sge = 1;
	attr.cap.max_recv_sge = 1;
	rc = rdma_create_qp(context->id, context->id->pd, &attr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_create_qp");
		return rc;
	}

	/* reduce posted wr limits further if qp requires it */
	context->max_posted_wr = MIN(context->max_posted_wr, attr.cap.max_recv_wr);
	context->min_posted_wr =
		MIN(context->min_posted_wr, context->max_posted_wr);

	/* posted wr limits will not be updated further, set min_ack */
	context->min_ack =
		context->min_posted_wr / config->signal_receive_min_ack_part;

	/* get MTU */
	struct ibv_port_attr port_attr;
	rc = ibv_query_port(context->id->verbs, context->id->port_num, &port_attr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, rc, "ibv_query_port");
		return -1;
	}
	unsigned mtu = 1u << (port_attr.active_mtu + 7);

	/* set size of signal buffers to be maximum possible given mtu */
	context->shared->signal_msg_num_spectra =
		MAX_VYS_SIGNAL_MSG_LENGTH(mtu);
	size_t sizeof_signal_msg =
		SIZEOF_VYS_SIGNAL_MSG(context->shared->signal_msg_num_spectra);

	/* create signal message buffer pool...num_signal_msg_buffers must be
	 * updated, as min_posted_wr may have been reduced. */
	num_signal_msg_buffers =
		context->min_posted_wr * config->signal_message_pool_overhead_factor;
	context->shared->signal_msg_buffers =
		vys_buffer_pool_new(num_signal_msg_buffers, sizeof_signal_msg);

	context->wcs = g_new(struct ibv_wc, context->max_posted_wr);

	/* register memory to receive signal messages */
	context->mr = rdma_reg_msgs(
		context->id,
		context->shared->signal_msg_buffers->pool,
		context->shared->signal_msg_buffers->pool_size);
	if (G_UNLIKELY(context->mr == NULL)) {
		VERB_ERR(error_record, errno, "rdma_reg_msgs");
		return -1;
	}

	/* join multicast */
	rc = rdma_join_multicast(context->id, &context->sockaddr, NULL);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_join_multicast");
		return -1;
	}
	context->in_multicast = true;
	struct rdma_cm_event *event;
	rc = get_cm_event(context->event_channel, RDMA_CM_EVENT_MULTICAST_JOIN,
	                  &event, error_record);
	if (G_UNLIKELY(rc != 0))
		return -1;
	context->remote_qpn = event->param.ud.qp_num;
	context->remote_qkey = event->param.ud.qkey;
	rdma_ack_cm_event(event);

	rc = set_nonblocking(context->comp_channel->fd);
	if (G_UNLIKELY(rc != 0)) {
		MSG_ERROR(error_record, errno,
		          "failed to set multicast completion channel to "
		          "non-blocking: %s", strerror(errno));
		return -1;
	}

	struct pollfd *pfd = &context->pollfds[RECEIVE_COMPLETION_FD_INDEX];
	pfd->fd = context->comp_channel->fd;
	pfd->events = POLLIN;
	pfd->revents = 0;
	return 0;
}

static int
leave_multicast(struct signal_receiver_context_ *context,
                struct vys_error_record **error_record)
{
	int rc = 0;
	if (context->in_multicast) {
		context->in_multicast = false;
		rc = rdma_leave_multicast(context->id, &context->sockaddr);
		if (G_UNLIKELY(rc != 0))
			VERB_ERR(error_record, errno, "rdma_leave_multicast");
		if (context->id != NULL) {
			struct ibv_qp_attr attr = {
				.qp_state = IBV_QPS_ERR
			};
			rc = ibv_modify_qp(context->id->qp, &attr, IBV_QP_STATE);
			if (G_UNLIKELY(rc != 0))
				VERB_ERR(error_record, errno, "ibv_modify_qp");
		}
	}
	return rc;
}

static int
stop_signal_receive(struct signal_receiver_context_ *context,
                    struct vys_error_record **error_record)
{
	int result = 0;
	int rc;

	rc = leave_multicast(context, error_record);
	if (G_UNLIKELY(rc != 0))
		result = -1;

	ack_completions(context, 1);
	if (context->id != NULL) {
		if (G_UNLIKELY(poll_completions(context, error_record) != 0))
			result = -1;
		rdma_destroy_qp(context->id);
	}

	if (context->rem_wrs != NULL) {
		recv_wr_free(context->rem_wrs);
		context->rem_wrs = NULL;
	}

	if (context->cq != NULL) {
		rc = ibv_destroy_cq(context->cq);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_record, errno, "ibv_destroy_cq");
			result = -1;
		}
		context->cq = NULL;
	}
	if (context->mr != NULL) {
		rc = rdma_dereg_mr(context->mr);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_record, errno, "rdma_dereg_mr");
			result = -1;
		}
		context->mr = NULL;
	}
	if (context->comp_channel != NULL) {
		ibv_destroy_comp_channel(context->comp_channel);
		context->comp_channel = NULL;
	}

	if (context->id != NULL) {
		rc = rdma_destroy_id(context->id);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_record, errno, "rdma_destroy_id");
			result = -1;
		}
		context->id = NULL;
	}
	if (context->event_channel != NULL) {
		rdma_destroy_event_channel(context->event_channel);
		context->event_channel = NULL;
	}
	if (context->wcs != NULL) {
		g_free(context->wcs);
		context->wcs = NULL;
	}
	context->pollfds[RECEIVE_COMPLETION_FD_INDEX].fd = -1;
	context->num_posted_wr = 0;
	return result;
}

static bool
new_wr(struct signal_receiver_context_ *context, struct recv_wr **wrs)
{
	bool result;
	struct vys_signal_msg *buff =
		vys_buffer_pool_pop(context->shared->signal_msg_buffers);
	if (G_LIKELY(buff != NULL)) {
		*wrs = recv_wr_prepend_new(
			*wrs,
			(uint64_t)buff,
			SIZEOF_VYS_SIGNAL_MSG(context->shared->signal_msg_num_spectra),
			context->mr->lkey);
		result = true;
	} else {
		result = false;
	}
	return result;
}

static void
ack_completions(struct signal_receiver_context_ *context, unsigned min_ack)
{
	if (context->num_not_ack >= min_ack) {
		if (context->cq != NULL)
			ibv_ack_cq_events(context->cq, context->num_not_ack);
		context->num_not_ack = 0;
	}
}

static int
poll_completions(struct signal_receiver_context_ *context,
                 struct vys_error_record **error_record)
{
	int nc = ibv_poll_cq(context->cq, context->num_posted_wr, context->wcs);
	if (G_UNLIKELY(nc < 0)) {
		VERB_ERR(error_record, errno, "ibv_poll_cq");
		return errno;
	}
	if (G_LIKELY(nc > 0)) {
		g_assert(context->num_posted_wr >= nc);
		context->num_posted_wr -= nc;
		if (G_LIKELY(context->state == STATE_RUN)) {
			/* for each completion event, process the event */
			for (int i = 0; i < nc; ++i) {
				struct vys_signal_msg *s_msg =
					(struct vys_signal_msg *)context->wcs[i].wr_id;
				struct data_path_message *dp_msg = data_path_message_new(
					context->shared->signal_msg_num_spectra);
				if (G_LIKELY(context->wcs[i].status == IBV_WC_SUCCESS)) {
					/* got a signal message */
					if (G_LIKELY(s_msg->payload.vys_version == VYS_VERSION)) {
						dp_msg->typ = DATA_PATH_SIGNAL_MSG;
						dp_msg->signal_msg = s_msg;
					} else {
						/* protocol version mismatch */
						dp_msg->typ = DATA_PATH_VERSION_MISMATCH;
						dp_msg->received_message_version =
							s_msg->payload.vys_version;
						/* put signal message buffer back into pool */
						vys_buffer_pool_push(
							context->shared->signal_msg_buffers, s_msg);
					}
				} else {
					/* failed receive, put signal message buffer back into
					 * pool */
					vys_buffer_pool_push(
						context->shared->signal_msg_buffers, s_msg);
					/* notify downstream of receive failure */
					dp_msg->typ = DATA_PATH_RECEIVE_FAIL;
					dp_msg->wc_status = context->wcs[i].status;
				}
				/* send data_path_message downstream */
				g_async_queue_push(context->shared->signal_msg_queue, dp_msg);
			}
		} else {
			for (int i = 0; i < nc; ++i) {
				struct vys_signal_msg *s_msg =
					(struct vys_signal_msg *)context->wcs[i].wr_id;
				vys_buffer_pool_push(context->shared->signal_msg_buffers,
				                     s_msg);
			}
		}
	}
	return 0;
}

static unsigned
create_new_wrs(struct signal_receiver_context_ *context)
{
	unsigned result = 0;
	if (G_LIKELY(context->state == STATE_RUN)) {
		/* try to create more work requests if we're below the max, and the
		 * last attempt to obtain a buffer from the pool succeeded */
		bool buffers_exhausted = false;
		while (!buffers_exhausted
		       && (context->num_posted_wr + result < context->max_posted_wr)) {
			buffers_exhausted = !new_wr(context, &context->rem_wrs);
			if (!buffers_exhausted) ++result;
		}
		if (buffers_exhausted
		    && context->num_posted_wr + result < context->min_posted_wr) {
			struct data_path_message *dp_msg =
				data_path_message_new(context->shared->signal_msg_num_spectra);
			dp_msg->typ = DATA_PATH_BUFFER_STARVATION;
			g_async_queue_push(context->shared->signal_msg_queue, dp_msg);
		}
		result = false;
	}
	return result;
}

static int
post_wrs(struct signal_receiver_context_ *context,
         struct vys_error_record **error_record)
{
	int rc = 0;
	if (G_LIKELY(context->state == STATE_RUN)) {
		if (G_LIKELY(context->rem_wrs != NULL)) {
			struct recv_wr *wrs = context->rem_wrs;
			/* post wrs */
			context->rem_wrs = NULL;
			rc = ibv_post_recv(
				context->id->qp,
				&wrs->ibv_recv_wr,
				(struct ibv_recv_wr **)&context->rem_wrs);
			if (G_LIKELY(rc == 0 || rc == ENOMEM)) {
				rc = 0;
				struct recv_wr *last_wr = NULL;
				struct recv_wr *next_wr = wrs;
				while (next_wr != context->rem_wrs) {
					context->num_posted_wr++;
					last_wr = next_wr;
					next_wr = recv_wr_next(last_wr);
				}
				if (G_LIKELY(last_wr != NULL)) {
					last_wr->ibv_recv_wr.next = NULL;
					recv_wr_free(wrs);
				}
			} else {
				VERB_ERR(error_record, rc, "ibv_post_recv");
			}
		}
		/* update underflow flag */
		bool in_underflow =
			context->num_posted_wr <=
			context->shared->handle->config.
			signal_message_receive_queue_underflow_level;
		if (context->in_underflow) {
			context->in_underflow = in_underflow;
		} else if (in_underflow) {
			/* transitioned from not-underflow to underflow...send message */
			context->in_underflow = true;
			struct data_path_message *dp_msg =
				data_path_message_new(
					context->shared->signal_msg_num_spectra);
			dp_msg->typ = DATA_PATH_RECEIVE_UNDERFLOW;
			g_async_queue_push(context->shared->signal_msg_queue, dp_msg);
		}
	} else if (context->rem_wrs != NULL) {
		recv_wr_free(context->rem_wrs);
		context->rem_wrs = NULL;
	}
	return rc;
}

static int
on_receive_completion(struct signal_receiver_context_ *context,
                      struct vys_error_record **error_record)
{
	/* get the completion event */
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int rc = ibv_get_cq_event(context->comp_channel, &ev_cq, &ev_ctx);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "ibv_get_cq_event");
		return rc;
	}
	g_assert(ev_cq == context->cq);

	/* acknowledge completion (maybe) */
	context->num_not_ack++;
	ack_completions(context, context->min_ack);

	/* post new completion notification request */
	rc = ibv_req_notify_cq(context->cq, 0);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, rc, "ibv_req_notify_cq");
		return -1;
	}

	rc = poll_completions(context, error_record);
	if (G_UNLIKELY(rc != 0))
		return -1;

	create_new_wrs(context);
	rc = post_wrs(context, error_record);

	return rc;
}

static int
to_quit_state(struct signal_receiver_context_ *context,
              struct data_path_message *quit_msg,
              struct vys_error_record **error_record)
{
	g_assert(context->state != STATE_DONE);
	if (quit_msg == NULL) {
		quit_msg =
			data_path_message_new(context->shared->signal_msg_num_spectra);
		quit_msg->typ = DATA_PATH_QUIT;
	}
	g_async_queue_push(context->shared->signal_msg_queue, quit_msg);
	int rc = 0;
	if (context->state != STATE_QUIT)
		rc = leave_multicast(context, error_record);
	context->state = STATE_QUIT;
	return rc;
}

static int
on_loop_input(struct signal_receiver_context_ *context,
              struct vys_error_record **error_record)
{
	struct data_path_message *msg;
	int rc = 0;
	ssize_t num_read = 0;
	do {
		ssize_t n = read(context->shared->loop_fd, (void *)&msg + num_read,
		                 sizeof(msg) - num_read);
		if (G_LIKELY(n >= 0)) {
			num_read += n;
		} else if (errno != EINTR && n < 0) {
			MSG_ERROR(error_record, errno, "Failed to read from loop pipe: %s",
			          strerror(errno));
			rc = -1;
		}
	} while (num_read < sizeof(msg) && rc == 0);
	if (rc == 0) {
		if (msg->typ == DATA_PATH_QUIT) {
			rc = to_quit_state(context, msg, error_record);
		} else if (msg->typ == DATA_PATH_END) {
			context->state = STATE_DONE;
			context->end_msg = msg;
		}
	}
	return rc;
}

static int
on_shutdown_timer_event(struct signal_receiver_context_ *context,
                        struct vys_error_record **error_record)
{
	uint64_t n;
	int rc = 0;
	size_t count = 0;
	do {
		ssize_t c = read(context->pollfds[SHUTDOWN_TIMER_FD_INDEX].fd,
		                 (void *)&n + count, sizeof(n) - count);
		if (G_LIKELY(c >= 0)) {
			count += c;
		} else if (errno != EINTR && n < 0) {
			MSG_ERROR(error_record, errno,
			          "Failed to read from timer fd: %s\n",
			          strerror(errno));
			rc = -1;
		}
	} while (count < sizeof(n) && rc == 0);

	if (G_LIKELY(
		    rc == 0 &&
		    (context->state == STATE_INIT || context->state == STATE_RUN))) {
		bool in_shutdown;
		struct vysmaw_result *result;
		get_shutdown_parameters(context->shared->handle,
		                        &in_shutdown, &result);
		if (G_UNLIKELY(in_shutdown)) {
			rc = to_quit_state(context, NULL, error_record);
			if (result != NULL && result->code != VYSMAW_NO_ERROR) {
				if (result->syserr_desc != NULL) {
					MSG_ERROR(error_record, result->code, "%s",
					          result->syserr_desc);
					g_free(result->syserr_desc);
				} else if (result->code == VYSMAW_ERROR_BUFFPOOL){
					MSG_ERROR(error_record, result->code, "%s",
					          "Buffer pool accounting internal error");
				}
			}
			if (result != NULL) g_free(result);
		}
	}
	return rc;
}

static int
on_poll_events(struct signal_receiver_context_ *context,
               struct vys_error_record **error_record)
{
	int result = 0;
	for (unsigned i = 0; result == 0 && i < NUM_FDS; ++i) {
		if (G_UNLIKELY(context->pollfds[i].revents & (POLLHUP | POLLERR))) {
			MSG_ERROR(error_record, -1, "%s", "HUP or ERR on poll fd");
			result = -1;
		} else {
			switch (i) {
			case SHUTDOWN_TIMER_FD_INDEX:
				if (context->pollfds[i].revents & POLLIN)
					result = on_shutdown_timer_event(context, error_record);
				break;

			case RECEIVE_COMPLETION_FD_INDEX:
				if (context->pollfds[i].revents & POLLIN)
					result = on_receive_completion(context, error_record);
				break;

			case LOOP_FD_INDEX:
				if (context->pollfds[i].revents & POLLIN)
					result = on_loop_input(context, error_record);
				break;

			default:
				g_assert_not_reached();
				break;
			}
		}
	}
	return result;
}

static int
start_shutdown_timer(struct pollfd *pollfd, unsigned interval_ms,
                     struct vys_error_record **error_record)
{
	int result = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	pollfd->fd = result;
	pollfd->events = POLLIN;
	if (result >= 0) {
		time_t sec = interval_ms / 1000;
		long nsec = (interval_ms % 1000) * 1000000L;
		struct itimerspec itimerspec = {
			.it_interval = { .tv_sec = sec, .tv_nsec = nsec },
			.it_value = { .tv_sec = sec, .tv_nsec = nsec }
		};
		int rc = timerfd_settime(result, 0, &itimerspec, NULL);
		if (rc < 0) {
			MSG_ERROR(error_record, errno, "Failed to start shutdown timer: %s",
			          strerror(errno));
			stop_shutdown_timer(pollfd, error_record);
			return rc;
		}
	} else {
		MSG_ERROR(error_record, errno, "Failed to create shutdown timer: %s",
		          strerror(errno));
	}
	return result;
}

static int
stop_shutdown_timer(struct pollfd *pollfd,
                    struct vys_error_record **error_record)
{
	int rc = 0;
	if (pollfd->fd >= 0) {
		rc = close(pollfd->fd);
		if (rc < 0)
			MSG_ERROR(error_record, errno, "Failed to close shutdown timer: %s",
			          strerror(errno));
	}
	pollfd->fd = -1;
	return rc;
}

static int
start_loop_monitor(struct signal_receiver_context_ *context,
                   struct vys_error_record **error_record)
{
	struct pollfd *pollfd = &context->pollfds[LOOP_FD_INDEX];
	pollfd->fd = context->shared->loop_fd;
	pollfd->events = POLLIN;
	return 0;
}

static int
stop_loop_monitor(struct signal_receiver_context_ *context,
                  struct vys_error_record **error_record)
{
	int rc = close(context->shared->loop_fd);
	if (G_UNLIKELY(rc != 0))
		MSG_ERROR(error_record, errno, "Failed to close loop fd: %s",
		          strerror(errno));
	return rc;
}

static int
signal_receiver_loop(struct signal_receiver_context_ *context,
                     struct vys_error_record **error_record)
{
	int result = 0;
	bool quit = false;
	int rc;
	if (context->pollfds[RECEIVE_COMPLETION_FD_INDEX].fd != -1) {
		rc = ibv_req_notify_cq(context->cq, 0);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_record, rc, "ibv_req_notify_cq");
			return -1;
		}
		create_new_wrs(context);
		if (post_wrs(context, error_record) != 0) {
			to_quit_state(context, NULL, error_record);
			result = -1;
		}
	}
	while (!quit) {
		rc = 0;
		int nfd = poll(context->pollfds, NUM_FDS, -1);
		if (G_LIKELY(nfd > 0)) {
			rc = on_poll_events(context, error_record);
		} else if (G_UNLIKELY(nfd < 0) && errno != EINTR) {
			MSG_ERROR(error_record, errno, "Failed to poll fds: %s",
			          strerror(errno));
			rc = -1;
		}
		if (G_UNLIKELY(rc != 0)) {
			to_quit_state(context, NULL, error_record);
			result = -1;
		}
		quit = context->state == STATE_DONE && context->num_posted_wr == 0;
	}
	return result;
}

#define READY(gate) G_STMT_START {                                      \
		MUTEX_LOCK((gate)->mtx); \
		(gate)->signal_receiver_ready = true; \
		COND_SIGNAL((gate)->cond); \
		MUTEX_UNLOCK((gate)->mtx); \
	} G_STMT_END

void *
signal_receiver(struct signal_receiver_context *shared)
{

	struct vys_error_record *error_record = NULL;

	struct signal_receiver_context_ context;
	memset(&context, 0, sizeof(context));
	context.shared = shared;
	context.state = STATE_INIT;
	context.in_multicast = false;
	context.in_underflow = true;

	for (unsigned i = 0; i < NUM_FDS; ++i)
		context.pollfds[i].fd = -1;

	int rc = start_loop_monitor(&context, &error_record);
	g_assert(rc == 0);

	rc = start_shutdown_timer(
		&context.pollfds[SHUTDOWN_TIMER_FD_INDEX],
		shared->handle->config.shutdown_check_interval_ms,
		&error_record);
	if (rc < 0)
		goto signal_data_path_end_and_return;

	rc = start_signal_receive(&context, &error_record);
	if (rc < 0)
		goto signal_data_path_end_and_return;

	READY(&shared->handle->gate);

	context.state = STATE_RUN;
	rc = signal_receiver_loop(&context, &error_record);

signal_data_path_end_and_return:
	READY(&shared->handle->gate);

	/* initialization failures may result in not being in STATE_DONE state */
	if (context.state != STATE_DONE) {
		to_quit_state(&context, NULL, &error_record);
		/* polling loop will only poll the loop fd, as the others are now
		 * closed */
		signal_receiver_loop(&context, &error_record);
	}

	stop_signal_receive(&context, &error_record);

	stop_shutdown_timer(
		&context.pollfds[SHUTDOWN_TIMER_FD_INDEX], &error_record);

	stop_loop_monitor(&context, &error_record);

	g_assert(context.end_msg != NULL && context.end_msg->typ == DATA_PATH_END);
	context.end_msg->error_record =
		vys_error_record_concat(error_record, context.end_msg->error_record);
	g_async_queue_push(shared->signal_msg_queue, context.end_msg);

	g_async_queue_unref(shared->signal_msg_queue);

	g_free(shared);
	return NULL;
}

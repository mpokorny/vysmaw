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
	uint32_t remote_qpn;
	uint32_t remote_qkey;
	unsigned num_posted_wr;
	unsigned max_posted_wr;
	unsigned min_ack;
	unsigned num_not_ack;
	struct recv_wr *rem_wrs;
};

struct recv_wr {
	/* ibv_recv_wr element must remain the first element in this struct */
	struct ibv_recv_wr ibv_recv_wr;
	struct ibv_sge ibv_sge;
};

static struct recv_wr *recv_wr_new(
	uint64_t addr, uint32_t length, uint32_t lkey)
	__attribute__((returns_nonnull,malloc));
static void recv_wr_free1(struct recv_wr *wr)
	__attribute__((nonnull));
static struct recv_wr *recv_wr_prepend_new(
	struct recv_wr *wrs, uint64_t addr, uint32_t length, uint32_t lkey)
	__attribute__((returns_nonnull,malloc));
static void recv_wr_free(struct recv_wr *wrs);
static struct recv_wr *recv_wr_next(struct recv_wr *wr)
	__attribute__((nonnull));
static int get_cm_event(
	struct rdma_event_channel *channel, enum rdma_cm_event_type type,
	struct rdma_cm_event **out_ev, GSList **error_records)
	__attribute__((nonnull(1)));
static int resolve_addr(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static void set_max_posted_wr(
	struct signal_receiver_context_ *context, unsigned max_posted_wr)
	__attribute__((nonnull));
static int start_signal_receive(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static int stop_signal_receive(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static bool new_wr(
	struct signal_receiver_context_ *context, struct recv_wr **wrs)
	__attribute__((nonnull));
static void ack_completions(
	struct signal_receiver_context_ *context, unsigned min_ack)
	__attribute__((nonnull));
static int poll_completions(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull(1)));
static unsigned create_new_wrs(struct signal_receiver_context_ *context)
	__attribute__((nonnull));
static void post_wrs(
	struct signal_receiver_context_ *context, unsigned num_new_wrs)
	__attribute__((nonnull));
static int on_poll_events(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static int signal_receiver_loop(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static int on_receive_completion(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static void to_quit_state(struct signal_receiver_context_ *context,
                          struct data_path_message *msg)
	__attribute__((nonnull(1)));
static int on_loop_input(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static int on_shutdown_timer_event(
	struct signal_receiver_context_ *context, GSList **error_records)
	__attribute__((nonnull));
static int start_shutdown_timer(
	struct pollfd *pollfd, unsigned interval_ms, GSList **error_records)
	__attribute__((nonnull));
static int stop_shutdown_timer(
	struct pollfd *pollfd, GSList **error_records)
	__attribute__((nonnull));

static struct recv_wr *
recv_wr_new(uint64_t addr, uint32_t length, uint32_t lkey)
{
	struct recv_wr *result = g_slice_new(struct recv_wr);
	result->ibv_recv_wr.sg_list = &result->ibv_sge;
	result->ibv_recv_wr.num_sge = 1;
	result->ibv_recv_wr.next = NULL;
	result->ibv_sge.addr = addr;
	result->ibv_sge.length = length;
	result->ibv_sge.lkey = lkey;
}

static void
recv_wr_free1(struct recv_wr *wr)
{
	g_slice_free1(sizeof(struct recv_wr), wr);
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
             GSList **error_records)
{
	struct rdma_cm_event *event = NULL;

	int rc = rdma_get_cm_event(channel, &event);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_get_cm_event");
		return rc;
	}

	/* Verify the event is the expected type */
	if (G_UNLIKELY(event->event != type)) {
		MSG_ERROR(error_records, -event->status,
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
resolve_addr(struct signal_receiver_context_ *context, GSList **error_records)
{
	int rc;
	struct rdma_addrinfo *mcast_rai = NULL;

	struct rdma_addrinfo hints;
	memset(&hints, 0, sizeof (hints));

	hints.ai_port_space = RDMA_PS_UDP;

	char *bind_addr = get_ipoib_addr();
	if (G_UNLIKELY(bind_addr == NULL)) {
		MSG_ERROR(error_records, errno, "Failed to get IPOIB address: %s",
		          strerror(errno));
		rc = -1;
		goto resolve_addr_cleanup_and_return;
	}

	struct rdma_addrinfo *bind_rai = NULL;
	hints.ai_flags = RAI_PASSIVE;
	rc = rdma_getaddrinfo(bind_addr, NULL, &hints, &bind_rai);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_getaddrinfo (bind)");
		goto resolve_addr_cleanup_and_return;
	}

	/* bind to a specific adapter if requested to do so */
	rc = rdma_bind_addr(context->id, bind_rai->ai_src_addr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_bind_addr");
		goto resolve_addr_cleanup_and_return;
	}

	hints.ai_flags = 0;
	rc = rdma_getaddrinfo(
		(char *)context->shared->handle->config.signal_multicast_address, NULL,
		&hints, &mcast_rai);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_getaddrinfo (mcast)");
		goto resolve_addr_cleanup_and_return;
	}

	rc = rdma_resolve_addr(
		context->id,
		(bind_rai != NULL) ? bind_rai->ai_src_addr : NULL,
		mcast_rai->ai_dst_addr,
		context->shared->handle->config.resolve_addr_timeout_ms);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_resolve_addr");
		goto resolve_addr_cleanup_and_return;
	}

	rc = get_cm_event(
		context->event_channel, RDMA_CM_EVENT_ADDR_RESOLVED, NULL,
		error_records);
	if (G_UNLIKELY(rc != 0))
		goto resolve_addr_cleanup_and_return;

	memcpy(&context->sockaddr, mcast_rai->ai_dst_addr, sizeof(struct sockaddr));

resolve_addr_cleanup_and_return:
	if (bind_addr != NULL)
		g_free(bind_addr);
	return rc;
}

static void
set_max_posted_wr(struct signal_receiver_context_ *context,
                  unsigned max_posted_wr)
{
	context->max_posted_wr = max_posted_wr;
	context->min_ack =
		max_posted_wr
		/ context->shared->handle->config.signal_receive_min_ack_part;
}

static int
start_signal_receive(struct signal_receiver_context_ *context,
                     GSList **error_records)
{
	set_max_posted_wr(
		context,
		context->shared->handle->config.signal_receive_max_posted);
	context->num_posted_wr = 0;
	context->num_not_ack = 0;

	/* event channel */
	context->event_channel = rdma_create_event_channel();
	if (G_UNLIKELY(context->event_channel == NULL)) {
		VERB_ERR(error_records, errno, "rdma_create_event_channel");
		return -1;
	}
	int rc = set_nonblocking(context->event_channel->fd);
	if (G_UNLIKELY(rc != 0)) {
		MSG_ERROR(error_records, errno,
		          "failed to set multicast completion event channel to "
		          "non-blocking: %s", strerror(errno));
		return -1;
	}

	/* rdma id */
	rc = rdma_create_id(
		context->event_channel, &context->id, context, RDMA_PS_UDP);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_create_id");
		return -1;
	}

	/* resolve my and multicast addresses */
	rc = resolve_addr(context, error_records);
	if (G_UNLIKELY(rc != 0))
		return -1;

	/* get MTU */
	struct ibv_port_attr port_attr;
	rc = ibv_query_port(context->id->verbs, context->id->port_num, &port_attr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, rc, "ibv_query_port");
		return -1;
	}
	int mtu = 1 << (port_attr.active_mtu + 7);
	/* set size of signal buffers to be maximum possible given mtu */
	context->shared->signal_msg_num_spectra =
		(mtu - sizeof(struct signal_msg)) / sizeof(struct vysmaw_spectrum_info);
	size_t sizeof_signal_msg =
		SIZEOF_SIGNAL_MSG(context->shared->signal_msg_num_spectra);

	/* create signal message buffer pool */
	context->shared->signal_msg_buffers =
		buffer_pool_new(
			(context->shared->handle->config.signal_message_pool_size
			 / sizeof_signal_msg),
			sizeof_signal_msg);

	/* completion channel */
	context->comp_channel = ibv_create_comp_channel(context->id->verbs);
	if (G_UNLIKELY(context->comp_channel == NULL)) {
		VERB_ERR(error_records, errno, "ibv_create_comp_channel");
		return -1;
	}

	/* lower max_posted_wr if ib device requires it */
	struct ibv_device_attr dev_attr;
	rc = ibv_query_device(context->id->verbs, &dev_attr);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, rc, "ibv_query_device");
		return -1;
	}
	set_max_posted_wr(context, MIN(context->max_posted_wr, dev_attr.max_cqe));

	/* completion queue */
	context->cq = ibv_create_cq(context->id->verbs, context->max_posted_wr,
	                            NULL, context->comp_channel, 0);
	if (G_UNLIKELY(context->cq == NULL)) {
		VERB_ERR(error_records, errno, "ibv_create_cq");
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
		VERB_ERR(error_records, errno, "rdma_create_qp");
		return rc;
	}

	/* reduce max_posted_wr further if qp requires it */
	set_max_posted_wr(context,
	                  MIN(context->max_posted_wr, attr.cap.max_recv_wr));

	context->wcs = g_new(struct ibv_wc, context->max_posted_wr);

	/* register memory to receive signal messages */
	context->mr = rdma_reg_msgs(
		context->id,
		context->shared->signal_msg_buffers->pool,
		context->shared->signal_msg_buffers->pool_size);
	if (G_UNLIKELY(context->mr == NULL)) {
		VERB_ERR(error_records, errno, "rdma_reg_msgs");
		return -1;
	}

	/* join multicast */
	rc = rdma_join_multicast(context->id, &context->sockaddr, NULL);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "rdma_join_multicast");
		return -1;
	}
	struct rdma_cm_event *event;
	rc = get_cm_event(context->event_channel, RDMA_CM_EVENT_MULTICAST_JOIN,
	                  &event, error_records);
	if (G_UNLIKELY(rc != 0))
		return -1;
	context->remote_qpn = event->param.ud.qp_num;
	context->remote_qkey = event->param.ud.qkey;
	rdma_ack_cm_event(event);

	return 0;
}

static int
stop_signal_receive(struct signal_receiver_context_ *context,
                    GSList **error_records)
{
	int result = 0;
	int rc;
	ack_completions(context, 1);
	if (context->id != NULL) {
		rc = rdma_leave_multicast(context->id, &context->sockaddr);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_records, errno, "rdma_leave_multicast");
			result = -1;
		}
		if (context->id->qp != NULL)
			rdma_destroy_qp(context->id);
	}
	if (context->cq != NULL) {
		rc = ibv_destroy_cq(context->cq);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_records, errno, "ibv_destroy_cq");
			result = -1;
		}
	}
	if (context->mr != NULL) {
		rc = rdma_dereg_mr(context->mr);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_records, errno, "rdma_dereg_mr");
			result = -1;
		}
	}
	if (context->comp_channel != NULL)
		ibv_destroy_comp_channel(context->comp_channel);

	if (context->id != NULL) {
		rc = rdma_destroy_id(context->id);
		if (G_UNLIKELY(rc != 0)) {
			VERB_ERR(error_records, errno, "rdma_destroy_id");
			result = -1;
		}
	}
	if (context->wcs != NULL)
		g_free(context->wcs);

	context->pollfds[RECEIVE_COMPLETION_FD_INDEX].fd = -1;
	return result;
}

static bool
new_wr(struct signal_receiver_context_ *context, struct recv_wr **wrs)
{
	bool result;
	struct signal_msg *buff =
		buffer_pool_pop(context->shared->signal_msg_buffers);
	if (buff != NULL) {
		*wrs = recv_wr_prepend_new(
			*wrs,
			(uint64_t)buff,
			SIZEOF_SIGNAL_MSG(context->shared->signal_msg_num_spectra),
			context->mr->lkey);
		result = true;
	} else {
		struct data_path_message *dp_msg =
			data_path_message_new(context->shared->signal_msg_num_spectra);
		dp_msg->typ = DATA_PATH_BUFFER_STARVATION;
		g_async_queue_push(context->shared->signal_msg_queue, dp_msg);
		result = false;
	}
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
                 GSList **error_records)
{
	int nc = ibv_poll_cq(context->cq, context->num_posted_wr, context->wcs);
	if (G_UNLIKELY(nc < 0)) {
		VERB_ERR(error_records, errno, "ibv_poll_cq");
		return errno;
	}
	if (G_LIKELY(nc > 0)) {
		g_assert(context->num_posted_wr >= nc);
		bool buffers_exhausted = false;
		context->num_posted_wr -= nc;
		/* for each completion event, process the event */
		for (int i = 0; i < nc; ++i) {
			struct signal_msg *s_msg =
				(struct signal_msg *)context->wcs[i].wr_id;
			struct data_path_message *dp_msg =
				data_path_message_new(context->shared->signal_msg_num_spectra);
			if (G_LIKELY(context->wcs[i].status == IBV_WC_SUCCESS)) {
				/* got a signal message */
				dp_msg->typ = DATA_PATH_SIGNAL_MSG;
				dp_msg->signal_msg = s_msg;
			} else {
				/* failed receive, put signal message buffer back into pool */
				buffer_pool_push(context->shared->signal_msg_buffers, s_msg);
				/* notify downstream of receive failure */
				dp_msg->typ = DATA_PATH_RECEIVE_FAIL;
				dp_msg->wc_status = context->wcs[i].status;
			}
			/* send data_path_message downstream */
			g_async_queue_push(context->shared->signal_msg_queue, dp_msg);
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
			if (!buffers_exhausted) result++;
		}
	}
	return result;
}

static void
post_wrs(struct signal_receiver_context_ *context, unsigned num_new_wrs)
{
	if (G_LIKELY(context->rem_wrs != NULL)) {
		if (G_LIKELY(context->state == STATE_RUN)) {
			struct recv_wr *wrs = context->rem_wrs;
			context->rem_wrs = NULL;
			int rc = ibv_post_recv(
				context->id->qp,
				&wrs->ibv_recv_wr,
				(struct ibv_recv_wr **)&context->rem_wrs);
			if (G_LIKELY(rc == 0)) {
				context->num_posted_wr += num_new_wrs;
			} else {
				/* hold on to the failed work requests, free those posted
				 * successfully */
				/* TODO: this assumes that there's nothing wrong with the
				 * requests themselves, and that we've failed because of a
				 * filled receive queue...is there some way of not making that
				 * assumption? */
				struct recv_wr *last_wr = NULL;
				struct recv_wr *next_wr = wrs;
				while (next_wr != context->rem_wrs) {
					context->num_posted_wr++;
					last_wr = next_wr;
					next_wr = recv_wr_next(last_wr);
				}
				if (last_wr != NULL) last_wr->ibv_recv_wr.next = NULL;
				else wrs = NULL;
			}
			/* Free posted work requests. Note that wrs should point to the head
			 * of the list of successfully posted requests. */
			recv_wr_free(wrs);
		} else {
			recv_wr_free(context->rem_wrs);
			context->rem_wrs = NULL;
		}
	}
}

static int
on_receive_completion(struct signal_receiver_context_ *context,
                      GSList **error_records)
{
	/* get the completion event */
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int rc = ibv_get_cq_event(context->comp_channel, &ev_cq, &ev_ctx);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, errno, "ibv_get_cq_event");
		return rc;
	}
	g_assert(ev_cq == context->cq);

	/* acknowledge completion (maybe) */
	context->num_not_ack++;
	ack_completions(context, context->min_ack);

	/* post new completion notification request */
	rc = ibv_req_notify_cq(context->cq, 0);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_records, rc, "ibv_req_notify_cq");
		return -1;
	}

	rc = poll_completions(context, error_records);
	if (G_UNLIKELY(rc != 0))
		return -1;

	post_wrs(context, create_new_wrs(context));

	return 0;
}

static void
to_quit_state(struct signal_receiver_context_ *context,
              struct data_path_message *quit_msg)
{
	g_assert(context->state != STATE_DONE);
	if (quit_msg == NULL) {
		quit_msg =
			data_path_message_new(context->shared->signal_msg_num_spectra);
		quit_msg->typ = DATA_PATH_QUIT;
	}
	g_async_queue_push(context->shared->signal_msg_queue, quit_msg);
	context->state = STATE_QUIT;
}

static int
on_loop_input(struct signal_receiver_context_ *context, GSList **error_records)
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
			MSG_ERROR(error_records, errno, "Failed to read from loop pipe: %s",
			          strerror(errno));
			rc = -1;
		}
	} while (num_read < sizeof(msg) && rc == 0);
	if (rc == 0) {
		if (msg->typ == DATA_PATH_QUIT) {
			to_quit_state(context, msg);
		} else if (msg->typ == DATA_PATH_END) {
			context->state = STATE_DONE;
			context->end_msg = msg;
		}
	}
	return rc;
}

static int
on_shutdown_timer_event(struct signal_receiver_context_ *context,
                        GSList **error_records)
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
			MSG_ERROR(error_records, errno,
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
			to_quit_state(context, NULL);
			if (result != NULL && result->code != VYSMAW_NO_ERROR) {
				if (result->syserr_desc != NULL) {
					MSG_ERROR(error_records, result->code, "%s",
					          result->syserr_desc);
					g_free(result->syserr_desc);
				} else if (result->code == VYSMAW_ERROR_BUFFPOOL){
					MSG_ERROR(error_records, result->code, "%s",
					          "Buffer pool accounting internal error");
				}
			}
			if (result != NULL) g_free(result);
		}
	}
	return rc;
}

static int
on_poll_events(struct signal_receiver_context_ *context, GSList **error_records)
{
	int result = 0;
	for (unsigned i = 0; result == 0 && i < NUM_FDS; ++i) {
		if (G_UNLIKELY(context->pollfds[i].revents & (POLLHUP | POLLERR))) {
			MSG_ERROR(error_records, -1, "%s", "HUP or ERR on poll fd");
			result = -1;
		} else {
			switch (i) {
			case SHUTDOWN_TIMER_FD_INDEX:
				if (G_LIKELY(context->pollfds[i].revents & POLLIN))
					result = on_shutdown_timer_event(context, error_records);
				break;

			case RECEIVE_COMPLETION_FD_INDEX:
				if (G_LIKELY(context->pollfds[i].revents & POLLIN))
					result = on_receive_completion(context, error_records);
				break;

			case LOOP_FD_INDEX:
				if (G_LIKELY(context->pollfds[i].revents & POLLIN))
					result = on_loop_input(context, error_records);
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
                     GSList **error_records)
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
			MSG_ERROR(error_records, errno, "Failed to start shutdown timer: %s",
			          strerror(errno));
			stop_shutdown_timer(pollfd, error_records);
			return rc;
		}
	} else {
		MSG_ERROR(error_records, errno, "Failed to create shutdown timer: %s",
		          strerror(errno));
	}
	return result;
}

static int
stop_shutdown_timer(struct pollfd *pollfd, GSList **error_records)
{
	int rc = 0;
	if (pollfd->fd >= 0) {
		rc = close(pollfd->fd);
		if (rc < 0)
			MSG_ERROR(error_records, errno, "Failed to close shutdown timer: %s",
			          strerror(errno));
	}
	pollfd->fd = -1;
	return rc;
}

static int
start_loop_monitor(struct signal_receiver_context_ *context,
                   GSList **error_records)
{
	struct pollfd *pollfd = &context->pollfds[LOOP_FD_INDEX];
	pollfd->fd = context->shared->loop_fd;
	pollfd->events = POLLIN;
	return 0;
}

static int
stop_loop_monitor(struct signal_receiver_context_ *context,
                  GSList **error_records)
{
	int rc = close(context->shared->loop_fd);
	if (G_UNLIKELY(rc != 0))
		MSG_ERROR(error_records, errno, "Failed to close loop fd: %s",
		          strerror(errno));
	return rc;
}

static int
signal_receiver_loop(struct signal_receiver_context_ *context,
                     GSList **error_records)
{
	int result = 0;
	bool quit = false;
	while (!quit) {
		int rc = 0;
		int nfd = poll(context->pollfds, NUM_FDS, -1);
		if (G_LIKELY(nfd > 0)) {
			rc = on_poll_events(context, error_records);
		} else if (G_UNLIKELY(nfd < 0) && errno != EINTR) {
			MSG_ERROR(error_records, errno, "Failed to poll fds: %s",
			          strerror(errno));
			rc = -1;
		}
		if (G_UNLIKELY(rc != 0)) {
			to_quit_state(context, NULL);
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

	GSList *error_records = NULL;

	struct signal_receiver_context_ context;
	memset(&context, 0, sizeof(context));
	context.shared = shared;
	context.state = STATE_INIT;

	for (unsigned i = 0; i < NUM_FDS; ++i)
		context.pollfds[i].fd = -1;

	int rc = start_loop_monitor(&context, &error_records);
	g_assert(rc == 0);

	rc = start_shutdown_timer(
		&context.pollfds[SHUTDOWN_TIMER_FD_INDEX],
		shared->handle->config.shutdown_check_interval_ms,
		&error_records);
	if (rc < 0)
		goto signal_data_path_end_and_return;

	rc = start_signal_receive(&context, &error_records);
	if (rc < 0)
		goto signal_data_path_end_and_return;

	READY(&shared->handle->gate);

	context.state = STATE_RUN;
	rc = signal_receiver_loop(&context, &error_records);

signal_data_path_end_and_return:
	READY(&shared->handle->gate);

	/* initialization failures may result in not being in STATE_DONE state */
	if (context.state != STATE_DONE) {
		to_quit_state(&context, NULL);
		/* polling loop will only poll the loop fd, as the others are now
		 * closed */
		signal_receiver_loop(&context, &error_records);
	}

	stop_signal_receive(&context, &error_records);

	stop_shutdown_timer(
		&context.pollfds[SHUTDOWN_TIMER_FD_INDEX], &error_records);

	stop_loop_monitor(&context, &error_records);

	g_assert(context.end_msg != NULL && context.end_msg->typ == DATA_PATH_END);
	context.end_msg->error_records =
		g_slist_concat(error_records, context.end_msg->error_records);
	g_async_queue_push(shared->signal_msg_queue, context.end_msg);

	g_async_queue_unref(shared->signal_msg_queue);

	handle_unref(shared->handle);
	g_free(shared);
	return NULL;
}
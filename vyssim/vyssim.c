#include <mpi.h>
#include <vys.h>
#include <poll.h>
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define SIGNAL_MSG_MAX_POSTED 1000
#define SIGNAL_MSG_QUEUE_LENGTH (2 * SIGNAL_MSG_MAX_POSTED)
#define SIGNAL_MSG_BLOCK_LENGTH (4 * SIGNAL_MSG_QUEUE_LENGTH)
#define MAX_STOKES_INDICES 4

struct spectral_window_descriptor {
	unsigned index;
	uint8_t num_stokes_indices;
	unsigned stokes_indices[MAX_STOKES_INDICES];
};

struct client_connection_context {
	struct rdma_cm_id *id;
	struct ibv_mr *mr;
	bool established;
};

struct dataset_parameters {
	unsigned num_baselines;
	unsigned num_spectral_windows;
	unsigned num_stokes;
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
	GMutex *signal_msg_buffers_mtx;
	unsigned signal_msg_num_spectra;
	struct signal_msg *signal_msg_block;
	GTrashStack *signal_msg_buffers;
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

	GArray *restrict spectral_window_descriptors;

	GThread *gen_thread;

	struct signal_msg *queue[SIGNAL_MSG_QUEUE_LENGTH];
	unsigned num_queued;
	GMutex *queue_mutex;
	GCond *queue_changed_condition;

	GSList *connections;

	unsigned num_data_buffers;
	size_t data_buffer_block_size;
	float *data_buffer_block;
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

	unsigned data_buffer_length_sec;
	unsigned num_spw;
	struct spectral_window_descriptor *spw_descriptors;
};

int resolve_addr(
	struct vyssim_context *vyssim, struct vys_error_record **error_record)
	__attribute__((nonnull(1)));

int get_cm_event(
	struct rdma_event_channel *channel, enum rdma_cm_event_type type,
	struct rdma_cm_event **out_ev, struct vys_error_record **error_record)
	__attribute__((nonnull(1)));

int
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
	if (vyssim->bind_addr) {
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
		/* A PD is created when we bind. Copy it to the mcast_context so it can be
		 * used later on */
		ctx->pd = ctx->id->pd;
	}

	hints.ai_flags = 0;
	rc = rdma_getaddrinfo(vyssim->vconfig->signal_multicast_address, NULL,
	                      &hints, &mcast_rai);
	if (G_UNLIKELY(rc != 0)) {
		VERB_ERR(error_record, errno, "rdma_getaddrinfo (mcast)");
		return rc;
	}

	rc = rdma_resolve_addr(
		ctx->id,
		(bind_rai != NULL) ? bind_rai->ai_src_addr : NULL,
		mcast_rai->ai_dst_addr,
		vyssim->vconfig->resolve_addr_timeout_ms);
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

int
get_cm_event(struct rdma_event_channel *channel,
             enum rdma_cm_event_type type,
             struct rdma_cm_event **out_ev,
             struct vys_error_record **error_record)
{
	int rc;
	struct rdma_cm_event *event = NULL;

	rc = rdma_get_cm_event(channel, &event);
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

int
main(int argc, char *argv[])
{
	struct vyssim_context vyssim;
	memset(&vyssim, 0, sizeof(vyssim));

	int op;
	while ((op = getopt(argc, argv, "b:w:c:k:i:l:f:")) != -1) {
		switch (op) {
		case 'b':
			vyssim.params.num_baselines = (unsigned)atoi(optarg);
			break;

		case 'w':
			vyssim.params.num_spectral_windows = (unsigned)atoi(optarg);
			break;

		case 'c':
			vyssim.params.num_channels = (unsigned)atoi(optarg);
			break;

		case 'k':
			vyssim.params.num_stokes = (unsigned)atoi(optarg);
			break;

		case 'i':
			vyssim.params.integration_time_microsec = (unsigned)atoi(optarg);
			break;

		case 'l':
			vyssim.mcast_ctx.signal_msg_num_spectra = (unsigned)atoi(optarg);
			break;

		case 'f':
			vyssim.data_buffer_length_sec = (unsigned)atoi(optarg);
			break;

		default:
			fprintf(stderr,
			        "usage: %s "
			        "-l signal_msg_num_spectra "
			        "-f data_buffer_length(sec) "
			        "-b num_baselines -w num_spectral_windows "
			        "-c num_channels -k num_stokes "
			        "-i integration_time_microsec\n",
			        argv[0]);
			goto cleanup_and_return;
			break;
		}
	}

	if (!(vyssim.params.num_stokes == 1 || vyssim.params.num_stokes == 2
	      || vyssim.params.num_stokes == 4)) {
		fprintf(stderr, "num_stokes must be 1, 2, or 4\n");
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

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif

	// TODO: verify MPI thread level
	int provided;
	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &provided);
	if (provided < MPI_THREAD_MULTIPLE) {
		fprintf(stderr, "unable to support MPI_THREAD_MULTIPLE\n");
		goto cleanup_and_return;
	}

	int rank;
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	int num_servers;
	MPI_Comm_size(MPI_COMM_WORLD, &num_servers);

	/* adjust parameter values */
	if (vyssim.mcast_ctx.signal_msg_num_spectra < 1) {
		fprintf(stderr, "using signal msg block length value of 1\n");
		vyssim.mcast_ctx.signal_msg_num_spectra = 1;
	}
	if (vyssim.data_buffer_length_sec < 1) {
		fprintf(stderr, "using data buffer length value of 1 sec\n");
		vyssim.data_buffer_length_sec = 1;
	}

	/* distribute products among all servers */
	unsigned sto_group_size =
		(vyssim.params.num_spectral_windows * vyssim.params.num_stokes)
		/ num_servers;// min number of products per server
	if (sto_group_size == 0) {
		fprintf(stderr,
		        "require reduced number of servers (no more than %u for "
		        "provided configuration)\n",
		        vyssim.params.num_spectral_windows *
		        vyssim.params.num_stokes);
		goto cleanup_and_return;
	}
	/* min power of two products per server*/
	sto_group_size =
		1 << g_bit_nth_msf(sto_group_size, 8 * sizeof(unsigned));
	/* distribute by no more than num_stokes products at a time */
	sto_group_size = MIN(sto_group_size, vyssim.params.num_stokes);
	/* number of groups a spectral window's stokes products are divided into */
	unsigned num_sto_groups = vyssim.params.num_stokes / sto_group_size;
	/* total number of groups of stokes products to distribute  */
	unsigned num_groups =
		vyssim.params.num_spectral_windows * num_sto_groups;
	/* distribute groups (spectral window plus a number of stokes products) in
	 * round-robin order to all processes (servers) */
	GArray *spws = g_array_new(
		FALSE, FALSE, sizeof(struct spectral_window_descriptor));
	for (unsigned grp = rank; grp < num_groups; grp += num_servers) {
		unsigned sto_group = grp % num_sto_groups;
		struct spectral_window_descriptor spw_desc = {
			.index = grp / num_sto_groups,
			.num_stokes_indices = sto_group_size
		};
		for (unsigned s = 0; s < sto_group_size; ++s)
			spw_desc.stokes_indices[s] = sto_group * sto_group_size + s;
		g_array_append_val(spws, spw_desc);
	}
	vyssim.num_spw = spws->len;
	vyssim.spw_descriptors =
		(struct spectral_window_descriptor *)g_array_free(spws, FALSE);

	// TODO: allow configuration file path
	vyssim.vconfig = vys_configuration_new(NULL);

cleanup_and_return:
	if (vyssim.vconfig != NULL)
		vys_configuration_free(vyssim.vconfig);
	if (vyssim.spw_descriptors != NULL)
		g_free(vyssim.spw_descriptors);
	if (vyssim.bind_addr != NULL)
		g_free(vyssim.bind_addr);
	int flag;
	MPI_Initialized(&flag);
	if (flag != 0) MPI_Finalize();
	return 0;
}

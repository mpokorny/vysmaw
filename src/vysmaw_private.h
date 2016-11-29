#ifndef VYSMAW_PRIVATE_H_
#define VYSMAW_PRIVATE_H_

#include <vysmaw.h>
#include <buffer_pool.h>
#include <glib.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_verbs.h>
#include <poll.h>

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
			GError *_err = NULL; \
			GThread *_result = g_thread_create((func), (data), true, &_err); \
			if (_err != NULL) { \
				g_error("Failed to start thread: %s", _err->message); \
				g_error_free(_err); \
			} \
			_result; })
# define Mutex GMutex *
# define MUTEX_INIT(m) { m = g_mutex_new(); }
# define MUTEX_CLEAR(m) g_mutex_free(m)
# define MUTEX_LOCK(m) g_mutex_lock(m)
# define MUTEX_UNLOCK(m) g_mutex_unlock(m)
# define RecMutex GStaticRecMutex
# define REC_MUTEX_INIT g_static_rec_mutex_init
# define REC_MUTEX_CLEAR g_static_rec_mutex_free
# define REC_MUTEX_LOCK g_static_rec_mutex_lock
# define REC_MUTEX_UNLOCK g_static_rec_mutex_unlock
# define Cond GCond *
# define COND_INIT(c) { c = g_cond_new(); }
# define COND_CLEAR(c) g_cond_free(c)
# define COND_WAIT(c, m) g_cond_wait(c, m)
# define COND_SIGNAL(c) g_cond_signal(c)
#endif

#define MSG_ERROR(records, err, format, ...)                            \
	{ *(records) = \
			g_slist_prepend(*(records), \
			                error_record_desc_dup_printf( \
				                (err), G_STRLOC ": " format, ##__VA_ARGS__)); }

#define VERB_ERR(records, err, fn)                                      \
	MSG_ERROR(records, err, "%s failed: %s", fn, strerror(err))

struct _vysmaw_message_queue {
	GAsyncQueue *q;
	unsigned depth;
	unsigned num_overflow;
};

struct spectrum_buffer_pool {
	int refcount;
	struct buffer_pool *pool;
};

typedef GSequence *spectrum_buffer_pool_collection;
typedef void *pool_id_t;

typedef void *(*new_valid_buffer)(vysmaw_handle handle, size_t buffer_size,
                                  pool_id_t *pool_id);
typedef struct spectrum_buffer_pool *(*lookup_buffer_pool)(
	struct vysmaw_message *message);
typedef GSList *(*list_buffer_pools)(vysmaw_handle handle);

struct consumer {
	struct _vysmaw_message_queue queue;
	vysmaw_spectrum_filter spectrum_filter_fn;
	GArray *pass_filter_array;
	void *user_data;
};

struct service_gate {
	bool signal_receiver_ready;
	bool spectrum_selector_ready;
	bool spectrum_reader_ready;
	Mutex mtx;
	Cond cond;
};

struct _vysmaw_handle {
	int refcount;

	const struct vysmaw_configuration config;

	Mutex mtx;
	int in_shutdown; // true iff VYSMAW_MESSAGE_END has been posted
	struct vysmaw_result *result; // for passing errors from main thread to
								  // workers

	/* buffer pool (collection) */
	new_valid_buffer new_valid_buffer_fn;
	lookup_buffer_pool lookup_buffer_pool_fn;
	list_buffer_pools list_buffer_pools_fn;
	union {
		struct {
			Mutex pool_collection_mtx;
			spectrum_buffer_pool_collection pool_collection;
		};
		struct spectrum_buffer_pool *pool;
	};
	unsigned num_data_buffers_unavailable;
	unsigned num_signal_buffers_unavailable;

	/* message consumers */
	unsigned num_consumers;
	struct consumer *consumers;

	/* service threads */
	struct service_gate gate;
	GThread *signal_receiver_thread;
	GThread *spectrum_selector_thread;
	GThread *spectrum_reader_thread;
};

struct signal_msg_payload {
	struct sockaddr_in sockaddr;
	uint16_t num_channels;
	uint8_t stations[2];
	uint8_t spectral_window_index;
	uint8_t stokes_index;
	uint8_t num_spectra;
	struct vysmaw_spectrum_info infos[];
};

struct signal_msg {
	struct ibv_grh grh;
	struct signal_msg_payload payload;
};

#define SIZEOF_SIGNAL_MSG_PAYLOAD(n) \
	(sizeof(struct signal_msg_payload) + \
	 ((n) * sizeof(struct vysmaw_spectrum_info)))

#define SIZEOF_SIGNAL_MSG(n) \
	(sizeof(struct signal_msg) + ((n) * sizeof(struct vysmaw_spectrum_info)))

struct error_record {
	int errnum;
	char *desc;
};

#define DATA_PATH_MESSAGE_DESC_LEN 128

struct data_path_message {
	enum {
		DATA_PATH_SIGNAL_MSG,
		DATA_PATH_RECEIVE_FAIL,
		DATA_PATH_BUFFER_STARVATION,
		DATA_PATH_QUIT,
		DATA_PATH_END
	} typ;
	size_t message_size;
	union {
		enum ibv_wc_status wc_status;
		GSList *error_records;
		struct {
			struct signal_msg *signal_msg;
			GSList *consumers[];
		};
	};
};

extern vysmaw_handle handle_ref(vysmaw_handle handle)
	__attribute__((nonnull,returns_nonnull));
extern void handle_unref(vysmaw_handle handle)
	__attribute__((nonnull));
extern GSList *all_consumers(vysmaw_handle handle)
	__attribute__((nonnull,returns_nonnull,malloc));
extern vysmaw_message_queue message_queue_ref(vysmaw_message_queue queue)
	__attribute__((nonnull,returns_nonnull));
extern void message_queue_unref(vysmaw_message_queue queue)
	__attribute__((nonnull));
extern struct spectrum_buffer_pool *spectrum_buffer_pool_new(
	size_t buffer_size, size_t num_buffers)
	__attribute__((malloc,returns_nonnull));
extern struct spectrum_buffer_pool *spectrum_buffer_pool_ref(
	struct spectrum_buffer_pool *pool)
	__attribute__((nonnull,returns_nonnull));
extern void spectrum_buffer_pool_unref(struct spectrum_buffer_pool *buffer_pool)
	__attribute__((nonnull));
extern void *spectrum_buffer_pool_pop(struct spectrum_buffer_pool *buffer_pool)
	__attribute__((nonnull));
extern void spectrum_buffer_pool_push(
	struct spectrum_buffer_pool *buffer_pool, void *buffer)
	__attribute__((nonnull));
extern int compare_pool_buffer_sizes(
	const void *a, const void *b, void *unused __attribute__((unused)));
extern spectrum_buffer_pool_collection spectrum_buffer_pool_collection_new(
	void)
	__attribute__((returns_nonnull,malloc));
extern void spectrum_buffer_pool_collection_free(
	spectrum_buffer_pool_collection collection)
	__attribute__((nonnull));
extern struct spectrum_buffer_pool *spectrum_buffer_pool_collection_add(
	spectrum_buffer_pool_collection collection, size_t buffer_size,
	size_t num_buffers)
	__attribute__((nonnull,returns_nonnull,malloc));
extern GSequenceIter *spectrum_buffer_pool_collection_lookup_iter(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
	__attribute__((nonnull));
extern struct spectrum_buffer_pool *spectrum_buffer_pool_collection_lookup(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
	__attribute__((nonnull));
extern void spectrum_buffer_pool_collection_remove(
	spectrum_buffer_pool_collection collection, size_t buffer_size)
	__attribute__((nonnull));
extern void *new_valid_buffer_from_collection(
	vysmaw_handle handle, size_t buffer_size, pool_id_t *pool_id)
	__attribute__((nonnull));
extern void *new_valid_buffer_from_pool(
	vysmaw_handle handle, size_t buffer_size, pool_id_t *pool_id)
	__attribute__((nonnull));
extern void message_queue_force_push_one_unlocked(
	struct vysmaw_message *msg, vysmaw_message_queue queue)
	__attribute__((nonnull));
extern void message_queue_push_one_unlocked(
	struct vysmaw_message *msg, struct consumer *consumer)
	__attribute__((nonnull));
extern void begin_shutdown(vysmaw_handle handle, struct vysmaw_result *rc)
	__attribute__((nonnull(1)));
extern void get_shutdown_parameters(
	vysmaw_handle handle, bool *in_shutdown, struct vysmaw_result **rc)
	__attribute__((nonnull));
extern struct vysmaw_message *message_ref(
	struct vysmaw_message *message)
	__attribute__((nonnull,returns_nonnull));
struct vysmaw_message *message_queue_pop(vysmaw_message_queue queue)
	__attribute__((nonnull,returns_nonnull));
extern struct spectrum_buffer_pool *lookup_buffer_pool_from_collection(
	struct vysmaw_message *message)
	__attribute__((nonnull));
extern struct spectrum_buffer_pool *lookup_buffer_pool_from_pool(
	struct vysmaw_message *message)
	__attribute__((nonnull));
extern GSList *buffer_pool_list_from_collection(vysmaw_handle handle)
	__attribute__((nonnull,returns_nonnull,malloc));
extern GSList *buffer_pool_list_from_pool(vysmaw_handle handle)
	__attribute__((nonnull,returns_nonnull,malloc));
extern void init_consumer(
	vysmaw_spectrum_filter filter, void *user_data,
	vysmaw_message_queue *queue, GArray *consumers)
	__attribute__((nonnull));
extern void init_signal_receiver(
	vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
	struct buffer_pool **signal_msg_buffers,
	unsigned *signal_msg_num_spectra, int loop_fd)
	__attribute__((nonnull));
extern void init_spectrum_selector(
	vysmaw_handle handle, GAsyncQueue *signal_msg_queue,
	GAsyncQueue *read_request_queue, struct buffer_pool *signal_msg_buffers,
	unsigned signal_msg_num_spectra)
	__attribute__((nonnull));
extern void init_spectrum_reader(
	vysmaw_handle handle, GAsyncQueue *read_request_queue,
	struct buffer_pool *signal_msg_buffers, unsigned signal_msg_num_spectra,
	int loop_fd)
	__attribute__((nonnull));
extern int init_service_threads(vysmaw_handle handle)
	__attribute__((nonnull));
extern struct vysmaw_message *message_new(
	vysmaw_handle handle, enum vysmaw_message_type typ)
	__attribute__((malloc,nonnull,returns_nonnull));
extern struct vysmaw_message *data_buffer_starvation_message_new(
	vysmaw_handle handle, unsigned num_unavailable)
	__attribute__((nonnull,returns_nonnull,malloc));
extern struct vysmaw_message *signal_buffer_starvation_message_new(
	vysmaw_handle handle, unsigned num_unavailable)
	__attribute__((nonnull,returns_nonnull,malloc));
extern struct vysmaw_message *digest_failure_message_new(
	vysmaw_handle handle, const struct vysmaw_data_info *info)
	__attribute__((malloc,returns_nonnull,nonnull));
extern struct vysmaw_message *end_message_new(
	vysmaw_handle handle, const struct vysmaw_result *rc)
	__attribute__((malloc,returns_nonnull,nonnull));
extern struct vysmaw_message *queue_overflow_message_new(
	vysmaw_handle handle, unsigned num_overflow)
	__attribute__((nonnull,returns_nonnull,malloc));
extern struct vysmaw_message *signal_receive_failure_message_new(
	vysmaw_handle handle, enum ibv_wc_status status)
	__attribute__((nonnull,returns_nonnull,malloc));
extern void post_msg(vysmaw_handle handle, struct vysmaw_message *message)
	__attribute__((nonnull));
extern void post_data_buffer_starvation(vysmaw_handle handle)
	__attribute__((nonnull));
extern void post_signal_buffer_starvation(vysmaw_handle handle)
	__attribute__((nonnull));
extern void post_signal_receive_failure(
	vysmaw_handle handle, enum ibv_wc_status status)
	__attribute__((nonnull));
extern void vysmaw_message_free_resources(struct vysmaw_message *message)
	__attribute__((nonnull));

extern struct error_record *error_record_new(
	int errnum, char *desc)
	__attribute__((nonnull,returns_nonnull,malloc));
extern struct error_record *error_record_desc_dup(
	int errnum, const char *desc)
	__attribute__((nonnull,returns_nonnull,malloc));
extern struct error_record *error_record_desc_dup_printf(
	int errnum, const char *format, ...)
	__attribute__((nonnull,returns_nonnull,malloc,format(printf,2,3)));
extern void error_record_free(
	struct error_record *record)
	__attribute__((nonnull));

extern struct data_path_message *data_path_message_new(
	unsigned max_spectra_per_signal)
	__attribute__((malloc,returns_nonnull));
extern void data_path_message_free(struct data_path_message *msg)
	__attribute__((nonnull));

extern struct vysmaw_message *valid_buffer_message_new(
	vysmaw_handle handle, const struct vysmaw_data_info *info,
	pool_id_t *pool_id)
	__attribute__((nonnull,malloc));

extern void message_queues_push_unlocked(
	struct vysmaw_message *msg, GSList *consumers)
	__attribute__((nonnull(1)));
extern void message_queues_push(
	struct vysmaw_message *msg, GSList *consumers)
	__attribute__((nonnull(1)));

extern void mark_data_buffer_starvation(vysmaw_handle handle)
	__attribute__((nonnull));
extern void mark_signal_buffer_starvation(vysmaw_handle handle)
	__attribute__((nonnull));
extern void mark_signal_receive_failure(
	vysmaw_handle handle, enum ibv_wc_status status)
	__attribute__((nonnull));

extern char *get_ipoib_addr(void)
	__attribute__((malloc,nonnull));

extern int set_nonblocking(int fd);

static inline size_t spectrum_size(const struct vysmaw_data_info *info)
{
	return 2 * info->num_channels * sizeof(float);
}

extern GHashTable *register_spectrum_buffer_pools(
	vysmaw_handle handle, struct rdma_cm_id *id, GSList **error_records)
	__attribute__((nonnull));

extern unsigned sockaddr_hash(
	const struct sockaddr_in *sockaddr)
	__attribute__((pure,nonnull));
extern bool sockaddr_equal(
	const struct sockaddr_in *a, const struct sockaddr_in *b)
	__attribute__((pure,nonnull));
extern struct sockaddr_in *new_sockaddr_key(
	const struct sockaddr_in *sockaddr)
	__attribute__((pure,nonnull,returns_nonnull,malloc));
extern void free_sockaddr_key(
	struct sockaddr_in *sockaddr)
	__attribute__((nonnull));

extern void convert_valid_to_digest_failure(struct vysmaw_message *message)
	__attribute__((nonnull));
extern void convert_valid_to_rdma_read_failure(
	struct vysmaw_message *message, enum ibv_wc_status status)
	__attribute__((nonnull));

#endif /* VYSMAW_PRIVATE_H_ */

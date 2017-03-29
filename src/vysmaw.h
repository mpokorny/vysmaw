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
#ifndef VYSMAW_H_
#define VYSMAW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <vys.h>

struct vysmaw_configuration {
	struct vys_error_record *error_record;

	/* multicast address for signal messages from CBE containing available
	 * spectrum metadata; expected format is dotted quad IP address string */
	char signal_multicast_address[VYS_MULTICAST_ADDRESS_SIZE];

	/* Size of memory region for storing spectra retrieved via RDMA from the
	 * CBE. The memory region is allocated and registered for RDMA by the
	 * library. Memory registration affects memory management on the host, as it
	 * pins physical memory in the virtual address space -- too large an
	 * allocation may be detrimental to the application; too little, and the
	 * library may be unable to copy the data from the CBE when it becomes
	 * available, resulting in lost data. Note that one memory region of the
	 * given size will be allocated for every size of spectrum that is received
	 * by the client unless 'single_spectrum_buffer_pool' is true. */
	size_t spectrum_buffer_pool_size;

	/* Maintain a single pool containing buffers sized to accommodate the
	 * maximum expected size of a spectrum.
	 *
	 * WARNING: setting this parameter to 'false' is not recommended at this
	 * time, as the implementation is incomplete. */
	bool single_spectrum_buffer_pool;

	/* The maximum expected size in bytes of a single spectrum that the client
	 * will receive. Note that all spectra that exceed this size will not be
	 * sent to the client, regardless of the result of the client filter
	 * predicate. This value is ignored unless 'single_spectrum_buffer_pool' is
	 * true. */
	unsigned max_spectrum_buffer_size;

	/* Size of memory region for storing signal messages carrying spectrum
	 * metadata sent from all active CBE nodes. The memory region is allocated
	 * and registered for InfiniBand messaging by the library. Setting the value
	 * too low will cause the receiver to miss signal messages. Keep in mind
	 * that every client should be prepared to receive _all_ such signal
	 * messages sent from every CBE node. */
	size_t signal_message_pool_size;

	/* vysmaw clients can either connect to a (CBE) sending process (to read
	 * spectral data) immediately upon receipt of any signal message from that
	 * process, or wait until a signal message is received from the process
	 * which matches (one of) the client's spectrum filter(s). When
	 * 'eager_connect' is 'false', the connection occurs only after a spectrum
	 * filter match; set value to 'true' for the other behavior */
	bool eager_connect;

	/* When 'eager_connect' is true, the following sets the minimum time between
	 * attempts to connect to each sending process eagerly. (A value less than 0.1
	 * sec is ignored.)
	 */
	double eager_connect_idle_sec;

	/* Control disposition of client read requests (for spectral data) after
	 * initiating a connection request to a sending process, but prior to that
	 * connection becoming ready. A value of 'true' maintains read requests that
	 * arrive in such intervals in a queue for processing until after the
	 * connection is ready; a value of 'false' will ignore those requests. Note
	 * that for fast data streams resulting in many client read requests, the
	 * backlog can accumulate very quickly, and will take some time to
	 * resolve. */
	bool preconnect_backlog;

	/* Maximum depth of message queue. */
	unsigned max_depth_message_queue;

	/* Overhead needed to resume data flow after message queue overflow.
	 * Operational value will be limited to < max_depth_message_queue. */
	unsigned queue_resume_overhead;

	/* Maximum number of buffer starvation events to wait before sending a
	 * VYSMAW_MESSAGE_[DATA|SIGNAL]_BUFFER_STARVATION message.
	 *
	 * TODO: distinguish latency for data and signal buffers? */
	unsigned max_starvation_latency;

	/* Maximum number of vys_version mismatch events to wait before sending a
	 * VYSMAW_MESSAGE_VERSION_MISMATCH message. */
	unsigned max_version_mismatch_latency;

	/*
	 * The following are probably best left at their default values, but expert
	 * users may find them useful.
	 */

	/* timeout, in milliseconds, to resolve InfiniBand/RDMA route */
	unsigned resolve_route_timeout_ms;

	/* timeout, in milliseconds, to resolve InfiniBand/RDMA address */
	unsigned resolve_addr_timeout_ms;

	/* timeout, in seconds, to determine data server inactivity */
	unsigned inactive_server_timeout_sec;

	/* interval to check for shutdown, in milliseconds */
	unsigned shutdown_check_interval_ms;

	/* maximum number of posted (uncompleted) signal receive requests (may be
	 * automatically reduced by hardware and/or system limitations)*/
	unsigned signal_receive_max_posted;

	/* signal receive completions to acknowledge at a time, expressed as a part
	 * of the maximum number of posted work requests: minimum number
	 * acknowledged will be signal_receive_max_posted /
	 * signal_receive_min_ack_part */
	unsigned signal_receive_min_ack_part;

	/* maximum number of posted (uncompleted) rdma read requests (may be
	 * automatically reduced by hardware and/or system limitations) */
	unsigned rdma_read_max_posted;

	/* rdma read request completions to acknowledge at a time, expressed as a
	 * part of the maximum number of posted work requests: minimum number
	 * acknowledged will be rdma_read_max_posted / rdma_read_min_ack_part */
	unsigned rdma_read_min_ack_part;
};

struct vysmaw_data_info {
	uint64_t timestamp;
	uint16_t num_channels;
	uint16_t num_bins;
	uint16_t bin_stride; /* in number of channels */
	uint8_t stations[2];
	uint8_t spectral_window_index;
	uint8_t polarization_product;
};

/* vysmaw result codes
 *
 * Values below VYSMAW_ERROR_NON_FATAL_END are non-fatal results. Values above
 * VYSMAW_ERROR_NON_FATAL_END are fatal vysmaw errors; when a VYSMAW_MESSAGE_END
 * message with a value in this range is received by the client, no more vysmaw
 * functions using the associated handle should be called, and the application
 * will likely have to abort to exit (due to threads and other resources that
 * cannot be reliably reclaimed by vysmaw). Please report occurrences of such
 * errors to mpokorny@nrao.edu.
 */
struct vysmaw_result {
	enum {
		VYSMAW_NO_ERROR,
		VYSMAW_SYSERR,
		VYSMAW_ERROR_NON_FATAL_END,
		VYSMAW_ERROR_BUFFPOOL
	} code;
	char *syserr_desc;
};

/* Client reference for vysmaw resources
 *
 * Clients may run vysmaw "tasks" independently; resources are not shared
 * between different vysmaw "tasks", subject to hardware and system limitations.
 * A vysmaw handle is an opaque client reference to a single instance of a
 * vysmaw "task", comprising threads and other resource allocations that handle
 * the collection of data from the CBE. The value of a vysmaw_handle instance is
 * constant for a single vysmaw "task", and these values may be copied by the
 * client freely. Note, however, that all copies of a handle become invalid
 * after a call to vysmaw_shutdown().
 */
struct _vysmaw_handle;

typedef struct _vysmaw_handle *vysmaw_handle;

/* Messages passed from vysmaw to the client
 *
 * struct vysmaw_message is the type of all elements on the queue shared by a
 * vysmaw "task" and a client. Clients must ensure that for all such messages
 * pulled from a queue, vysmaw_message_unref() is called promptly thereafter.
 */
enum vysmaw_message_type {
	VYSMAW_MESSAGE_VALID_BUFFER,
	VYSMAW_MESSAGE_DIGEST_FAILURE, // failed to verify buffer digest
	VYSMAW_MESSAGE_QUEUE_OVERFLOW, // message queue overflow
	VYSMAW_MESSAGE_DATA_BUFFER_STARVATION, // data buffers unavailable
	VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION, // signal buffers unavailable
	VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE, // failure in receiving signal
										   // message
	VYSMAW_MESSAGE_RDMA_READ_FAILURE, // failure of rdma read of spectral data
	VYSMAW_MESSAGE_VERSION_MISMATCH, // vys_version field mismatch
	VYSMAW_MESSAGE_END // vysmaw_handle exited
};

#define RECEIVE_STATUS_LENGTH 64

struct vysmaw_message {
	int refcount;
	enum vysmaw_message_type typ;
	vysmaw_handle handle;
	union {
		/* VYSMAW_MESSAGE_VALID_BUFFER */
		struct {
			struct vysmaw_data_info info;
			size_t buffer_size;
			float *buffer;
		} valid_buffer;

		/* VYSMAW_MESSAGE_DIGEST_FAILURE */
		struct vysmaw_data_info digest_failure;

		/* VYSMAW_MESSAGE_QUEUE_OVERFLOW */
		unsigned num_overflow;

		/* VYSMAW_MESSAGE_DATA_BUFFER_STARVATION */
		unsigned num_data_buffers_unavailable;

		/* VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION */
		unsigned num_signal_buffers_unavailable;

		/* VYSMAW_MESSAGE_VERSION_MISMATCH */
		unsigned num_buffers_mismatched_version;

		/* VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE */
		char signal_receive_status[RECEIVE_STATUS_LENGTH];

		/* VYSMAW_MESSAGE_RDMA_READ_FAILURE */
		char rdma_read_status[RECEIVE_STATUS_LENGTH];

		/* VYSMAW_MESSAGE_END */
		struct vysmaw_result result;
	} content;
};

/* Spectrum filter predicate (callback)
 *
 * Clients are able to select which spectra they wish to receive from a vysmaw
 * "task" through the use of a function with this signature. The CBE nodes
 * broadcast spectrum metadata, and make the data available for reading via RDMA
 * for some period of time. It is up to each client to determine those spectra
 * it wishes to read from the CBE nodes by examining the metadata.
 *
 * The function is called by a vysmaw thread for subsets of spectrum metadata.
 * vysmaw clients should be aware that this function may be called very
 * frequently from a vysmaw thread, and the performance of vysmaw will be
 * affected by the time that is required to call this function. High performing
 * filter functions will perform minimal computation with good efficiency.
 *
 * The argument list of a vysmaw_spectrum_filter function comprises a sequence
 * of spectrum metadata, one element of user-supplied data, and a boolean-valued
 * output array that must be filled by this function. The metadata are provided
 * as a pair of station ids, a spectral window index, a polarization product
 * descriptor, an array of timestamps. Note that, for efficiency, the timestamps
 * are provided through 'struct vys_spectrum_info' values. 'num_infos' provides
 * the length of the 'infos' array, as well as the 'pass_filter' (output) array.
 * All elements in the 'pass_filter' array should be written by the function.
 * The element 'pass_filter[i]' should be set to 'true' if and only if the
 * client wishes to receive the data corresponding to 'infos[i]'.
 */
typedef void (*vysmaw_spectrum_filter)(
	const uint8_t stations[2], uint8_t spectral_window_index,
	uint8_t polarization_product, const struct vys_spectrum_info *infos,
	uint8_t num_infos, void *user_data, bool *pass_filter);

/* Message queue (FIFO) used to pass spectral data back to client.
 *
 * Clients must continue to pop elements from these queues until a message of
 * type VYSMAW_MESSAGE_END appears, after which the queue will be invalid, and
 * should no longer be used. Failure to get messages until the
 * VYSMAW_MESSAGE_END message will prevent a vysmaw "task" from releasing all
 * its resources.
 */
struct _vysmaw_message_queue;

typedef struct _vysmaw_message_queue *vysmaw_message_queue;

/* Single client data stream
 */
struct vysmaw_consumer {
	vysmaw_spectrum_filter filter;
	void *filter_data;
	vysmaw_message_queue queue;
};

/* Free resources allocated by, and associated with, a vysmaw_message.
 *
 * It is imperative that clients call this method for all received messages in a
 * timely manner. Failure to do so will consume memory into which the library
 * would otherwise copy spectra from the CBE (resulting in lost data), or result
 * in other resource leaks. */
extern void vysmaw_message_unref(struct vysmaw_message *message)
	__attribute__((nonnull));

/* Start vysmaw threads.
 *
 * The library will create a message queue for passing messages to the client,
 * returned in the 'queue' handle. To release resources used by the
 * vysmaw_handle, it is required that the client call vysmaw_shutdown(), as well
 * as popping messages off the queue until a VYSMAW_MESSAGE_END message is
 * received. Calling vysmaw_message_unref() on the VYSMAW_MESSAGE_END message
 * will release all remaining queue resources. The 'user_data' pointer will be
 * passed as an argument in all calls to the 'spectrum_filter' function.
 *
 * This function allows a single client to set up multiple filters and queues.
 * It is advisable for the distribution of messages from a single queue to
 * multiple threads, if desired, to be done by the client, and not by setting up
 * multiple queues with the same filter predicate, in order to prevent the
 * evaluation of the predicate multiple times for each argument query.
 */
extern vysmaw_handle vysmaw_start_(const struct vysmaw_configuration *config,
                                   unsigned num_consumers,
                                   struct vysmaw_consumer *consumers)
	__attribute__((nonnull(1,3),malloc,returns_nonnull));

/* Start vysmaw threads; as above, but more friendly for cython usage.
 */
extern vysmaw_handle vysmaw_start(const struct vysmaw_configuration *config,
                                  unsigned num_consumers,
                                  struct vysmaw_consumer **consumers)
	__attribute__((nonnull(1,3),malloc,returns_nonnull));

/* Shut down vysmaw threads.
 *
 * After calling this method, although the handle shall no longer be used by the
 * client, the client should continue to get messages from the associated
 * message queue until VYSMAW_MESSAGE_END appears (and call vysmaw_message_unref
 * on all such messages.)
 */
extern void vysmaw_shutdown(vysmaw_handle handle)
	__attribute__((nonnull));

/* Get a message from a message queue.
 *
 * Blocks until a message is available. It is the caller's responsibility to
 * call vysmaw_message_unref() promptly with the returned message to minimize
 * resource usage by the associated vysmaw_handle (as well as to allow a clean
 * shutdown of the vysmaw_handle resources after VYSMAW_MESSAGE_END is
 * received.) No attempt to retrieve messages from the queue shall be made after
 * a VYSMAW_MESSAGE_END appears.
 *
 * @see vysmaw_message_unref()
 */
extern struct vysmaw_message *vysmaw_message_queue_pop(
	vysmaw_message_queue queue)
	__attribute__((nonnull,returns_nonnull));

/* Get a message from a message queue, blocking for at most 'timeout'
 * microseconds.
 *
 * Returns NULL if timeout occurs.
 *
 * @see vysmaw_message_queue_pop()
 * @see vysmaw_message_unref()
 */
extern struct vysmaw_message *vysmaw_message_queue_timeout_pop(
	vysmaw_message_queue queue, uint64_t timeout)
	__attribute__((nonnull));

/* Get a message from a message queue if one is available.
 *
 * Returns NULL if no message was on the queue.
 *
 * @see vysmaw_message_queue_pop()
 * @see vysmaw_message_unref()
 */
extern struct vysmaw_message *vysmaw_message_queue_try_pop(
	vysmaw_message_queue queue)
	__attribute__((nonnull));

/* Get a configuration instance, filled with default values. Optionally provide
 * a path to a vysmaw configuration file.
 *
 * @see vysmaw_configuration_free()
 */
extern struct vysmaw_configuration *vysmaw_configuration_new(
	const char *path)
	__attribute__((malloc,returns_nonnull));

/* Free a configuration instance that was allocated using
 * vysmaw_configuration_new().
 *
 * @see vysmaw_configuration_new()
 */
extern void vysmaw_configuration_free(struct vysmaw_configuration *config)
	__attribute__((nonnull));

#ifdef __cplusplus
}
#endif

#endif /* VYSMAW_H_ */

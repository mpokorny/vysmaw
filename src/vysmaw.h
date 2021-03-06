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
#ifndef VYSMAW_H_
#define VYSMAW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <vys.h>
#include <complex.h>

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

  /* Minimum time that a buffer pool is not accessed before its resources will
     be reclaimed, in seconds. */
  unsigned spectrum_buffer_pool_min_idle_lifetime_sec;

  /* Limits on number of work requests to maintain on the receive queue for
   * signal messages. The lower limit should be at least the number of signal
   * messages that are expected to arrive in the period that it takes the
   * vysmaw signal_receiver loop to service the receive queue. Unfortunately
   * the time required for the aforementioned loop to complete is not known a
   * priori, so some tuning of the lower limit parameter by vysmaw
   * applications is expected. The upper limit is available to control
   * resource usage in the InfiniBand HCA (see
   * "signal_message_pool_overhead_factor" parameter to control total memory
   * assigned to signal messages.) */
  unsigned signal_message_receive_min_posted;
  unsigned signal_message_receive_max_posted;

  /* The number of signal messages in the registered memory region for signal
   * messages is determined by the product of the
   * "signal_message_receive_min_posted" parameter, the following
   * "signal_message_pool_overhead_factor" value, and the size of one signal
   * message (which will be close to the MTU size of the InfiniBand
   * network). The value of "signal_message_pool_overhead_factor" should be
   * based on the number of signal messages that are expected to be in use by
   * the vysmaw application through the consumer callbacks while the vysmaw
   * library maintains "signal_message_receive_min_posted" work requests for
   * receiving signal messages. The value of this parameter need not be an
   * integer, but its minimum value is 1. */
  double signal_message_pool_overhead_factor;

  /* Number of work requests on the signal message receive queue at which a
   * VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW message is created and sent
   * to consumer queues. Ideally, this level would be zero, but as there is no
   * signal available from a QP for that event, and can only be inferred by
   * comparing the number of receive requests vs the number of completion
   * queue entries, this level more accurately can be taken to mean that the
   * signal receive queue depth is "dangerously low". A vysmaw application is
   * in danger of missing signal messages when a receive queue underflow
   * occurs. */
  unsigned signal_message_receive_queue_underflow_level;

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

  /* Depth of message queue at which an alert message is generated. */
  unsigned message_queue_alert_depth;

  /* Interval at which message queue alerts are repeated, expressed as the
   * number of queue messages between alert messages. */
  unsigned message_queue_alert_interval;

  /* Maximum number of buffer starvation events to wait before sending a
   * VYSMAW_MESSAGE_DATA_BUFFER_STARVATION message. */
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

  /* number of signal receive completions to acknowledge at one time,
   * expressed as a part of the minimum number of posted work requests:
   * minimum number acknowledged will be signal_message_receive_min_posted /
   * signal_receive_min_ack_part */
  unsigned signal_receive_min_ack_part;

  /* maximum number of posted (uncompleted) rdma read requests (may be
   * automatically reduced by hardware and/or system limitations) */
  unsigned rdma_read_max_posted;

  /* rdma read request completions to acknowledge at one time */
  unsigned rdma_read_min_ack;
};

struct vysmaw_data_info {
  char config_id[VYS_CONFIG_ID_SIZE];
  uint64_t timestamp;
  uint16_t num_channels;
  uint16_t num_bins;
  uint16_t bin_stride; /* in number of channels */
  uint8_t stations[2];
  uint8_t baseband_index;
  uint8_t baseband_id;
  uint8_t spectral_window_index;
  uint8_t polarization_product_id;
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
  VYSMAW_MESSAGE_SPECTRA,
  VYSMAW_MESSAGE_QUEUE_ALERT, // message queue level alert
  VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION, // data spectra unavailable
  VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE, // failure in receiving signal
  // message
  VYSMAW_MESSAGE_VERSION_MISMATCH, // vys_version field mismatch
  VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW, // underflow on signal
  // receive queue
  VYSMAW_MESSAGE_END // vysmaw_handle exited
};

#define RECEIVE_STATUS_LENGTH 64

union vysmaw_spectrum_header {
  uint32_t id_num;
  char padding[VYS_SPECTRUM_OFFSET];
};

struct vysmaw_spectrum {
  uint64_t timestamp;
  bool failed_verification;
  char rdma_read_status[RECEIVE_STATUS_LENGTH];
  union vysmaw_spectrum_header *header;
  _Complex float *values;
};

struct vysmaw_message {
  int refcount;
  enum vysmaw_message_type typ;
  vysmaw_handle handle;
  union {
    /* VYSMAW_MESSAGE_SPECTRA */
    struct {
      // don't use timestamp in the following info field, use timestamp fields
      // in array of struct vysmaw_spectrum elements at the end of the
      // vysmaw_message
      struct vysmaw_data_info info;
      size_t spectrum_buffer_size;
      unsigned num_spectra;
      void *header_buffer;
      void *data_buffer;
    } spectra;

    /* VYSMAW_MESSAGE_QUEUE_ALERT */
    unsigned queue_depth;

    /* VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION */
    unsigned num_spectrum_buffers_unavailable;

    /* VYSMAW_MESSAGE_VERSION_MISMATCH */
    unsigned num_spectra_mismatched_version;

    /* VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE */
    char signal_receive_status[RECEIVE_STATUS_LENGTH];

    /* VYSMAW_MESSAGE_VERSION_MISMATCH */
    unsigned received_message_version;

    /* VYSMAW_MESSAGE_END */
    struct vysmaw_result result;
  } content;

  struct vysmaw_spectrum data[];
};

#define SIZEOF_VYSMAW_MESSAGE(n) (\
    sizeof(struct vysmaw_message) + (n) * sizeof(struct vysmaw_spectrum))

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
  const char *config_id,
  const uint8_t stations[2], uint8_t baseband_index,
  uint8_t baseband_id, uint8_t spectral_window_index,
  uint8_t polarization_product_id,
  const struct vys_spectrum_info *infos, uint8_t num_infos,
  void *user_data, bool *pass_filter);

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
 */
extern vysmaw_handle vysmaw_start(const struct vysmaw_configuration *config,
                                  struct vysmaw_consumer *consumer)
  __attribute__((nonnull,malloc,returns_nonnull));


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

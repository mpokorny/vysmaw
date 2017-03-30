# coding: utf-8
#
# Copyright © 2016 Associated Universities, Inc. Washington DC, USA.
#
# This file is part of vysmaw.
#
# vysmaw is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# vysmaw is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# vysmaw.  If not, see <http://www.gnu.org/licenses/>.
#
from libc.stdint cimport *
from libc cimport stddef
from libcpp cimport bool

cdef extern from "vysmaw.h":

    DEF VYS_DATA_DIGEST_SIZE = 16

    DEF VYS_MULTICAST_ADDRESS_SIZE = 32

    DEF VYSMAW_RECEIVE_STATUS_LENGTH = 64

    struct vysmaw_configuration:
        char signal_multicast_address[VYS_MULTICAST_ADDRESS_SIZE]
        stddef.size_t spectrum_buffer_pool_size
        bool single_spectrum_buffer_pool
        unsigned max_spectrum_buffer_size
        stddef.size_t signal_message_pool_size
        bool eager_connect
        double eager_connect_idle_sec
        bool preconnect_backlog
        unsigned max_depth_message_queue
        unsigned queue_resume_overhead
        unsigned max_starvation_latency
        unsigned resolve_route_timeout_ms
        unsigned resolve_addr_timeout_ms
        unsigned inactive_server_timeout_sec
        unsigned shutdown_check_interval_ms
        unsigned signal_receive_max_posted
        unsigned signal_receive_min_ack_part
        unsigned rdma_read_max_posted
        unsigned rdma_read_min_ack_part

    struct vysmaw_data_info:
        uint64_t timestamp
        uint16_t num_channels
        uint16_t num_bins
        uint16_t bin_stride
        uint8_t stations[2]
        uint8_t spectral_window_index
        uint8_t baseband_id
        uint8_t polarization_product_id

    struct vys_spectrum_info:
        uint64_t data_addr
        uint64_t timestamp
        uint8_t digest[VYS_DATA_DIGEST_SIZE]

    enum result_code:
        VYSMAW_NO_ERROR,
        VYSMAW_SYSERR,
        VYSMAW_ERROR_USER_END,
        VYSMAW_ERROR_BUFFPOOL

    struct vysmaw_result:
        result_code code
        char *syserr_desc

    struct _vysmaw_handle:
        pass

    ctypedef _vysmaw_handle * vysmaw_handle
    
    enum vysmaw_message_type:
        VYSMAW_MESSAGE_VALID_BUFFER,
        VYSMAW_MESSAGE_DIGEST_FAILURE,
        VYSMAW_MESSAGE_QUEUE_OVERFLOW,
        VYSMAW_MESSAGE_DATA_BUFFER_STARVATION,
        VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION,
        VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE,
        VYSMAW_MESSAGE_RDMA_READ_FAILURE,
        VYSMAW_MESSAGE_END

    struct message_valid_buffer:
        vysmaw_data_info info
        stddef.size_t buffer_size
        float *buffer

    union message_content:
        message_valid_buffer valid_buffer
        vysmaw_data_info digest_failure
        unsigned num_overflow
        unsigned num_data_buffers_unavailable
        unsigned num_signal_buffers_unavailable
        char signal_receive_status[VYSMAW_RECEIVE_STATUS_LENGTH]
        char rdma_read_status[VYSMAW_RECEIVE_STATUS_LENGTH]
        vysmaw_result result

    struct vysmaw_message:
        int refcount
        vysmaw_message_type typ
        vysmaw_handle handle
        message_content content

    struct _vysmaw_message_queue:
        pass

    ctypedef _vysmaw_message_queue *vysmaw_message_queue

    ctypedef void (*vysmaw_spectrum_filter)(
        const uint8_t *stations, uint8_t spectral_window_index,
        uint8_t baseband_id, uint8_t polarization_product_id,
        const vys_spectrum_info *infos, uint8_t num_infos,
        void *user_data, bool *pass_filter) nogil

    struct vysmaw_consumer:
        vysmaw_spectrum_filter filter
        void *filter_data
        vysmaw_message_queue queue

    vysmaw_handle vysmaw_start(vysmaw_configuration *config,
                               unsigned num_consumers,
                               vysmaw_consumer **consumers) nogil

    vysmaw_configuration *vysmaw_configuration_new(char *path) nogil

    void vysmaw_configuration_free(vysmaw_configuration *config)

    void vysmaw_shutdown(vysmaw_handle handle)

    void vysmaw_message_unref(vysmaw_message *message)

    vysmaw_message *vysmaw_message_queue_pop(vysmaw_message_queue queue) nogil

    vysmaw_message *vysmaw_message_queue_timeout_pop(
        vysmaw_message_queue queue,
        uint64_t timeout) nogil

    vysmaw_message *vysmaw_message_queue_try_pop(vysmaw_message_queue queue)

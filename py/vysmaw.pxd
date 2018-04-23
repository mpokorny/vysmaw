# coding: iso-8859-1
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

    int VYS_SPECTRUM_OFFSET = 32

    DEF VYS_MULTICAST_ADDRESS_SIZE = 32

    DEF VYS_CONFIG_ID_SIZE = 60

    int VYS_POLARIZATION_PRODUCT_AA = 0
    int VYS_POLARIZATION_PRODUCT_AB = 1
    int VYS_POLARIZATION_PRODUCT_BA = 2
    int VYS_POLARIZATION_PRODUCT_BB = 3
    int VYS_POLARIZATION_PRODUCT_UNKNOWN = 4

    int VYS_BASEBAND_A1C1_3BIT = 0
    int VYS_BASEBAND_A2C2_3BIT = 1
    int VYS_BASEBAND_AC_8BIT = 2
    int VYS_BASEBAND_B1D1_3BIT = 3
    int VYS_BASEBAND_B2D2_3BIT = 4
    int VYS_BASEBAND_BD_8BIT = 5
    int VYS_BASEBAND_UNKNOWN = 6

    DEF VYSMAW_RECEIVE_STATUS_LENGTH = 64

    struct vysmaw_configuration:
        char signal_multicast_address[VYS_MULTICAST_ADDRESS_SIZE]
        stddef.size_t spectrum_buffer_pool_size
        bool single_spectrum_buffer_pool
        unsigned max_spectrum_buffer_size
        unsigned signal_message_receive_min_posted
        unsigned signal_message_receive_max_posted
        double signal_message_pool_overhead_factor
        unsigned signal_message_receive_queue_underflow_level
        bool eager_connect
        double eager_connect_idle_sec
        bool preconnect_backlog
        unsigned message_queue_alert_depth
        unsigned message_queue_alert_interval
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
        char config_id[VYS_CONFIG_ID_SIZE]
        uint64_t timestamp
        uint16_t num_channels
        uint16_t num_bins
        uint16_t bin_stride
        uint8_t stations[2]
        uint8_t baseband_index
        uint8_t baseband_id
        uint8_t spectral_window_index
        uint8_t polarization_product_id

    struct vys_spectrum_info:
        uint64_t data_addr
        uint64_t timestamp
        uint32_t id_num

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
        VYSMAW_MESSAGE_ID_FAILURE,
        VYSMAW_MESSAGE_QUEUE_ALERT,
        VYSMAW_MESSAGE_DATA_BUFFER_STARVATION,
        VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION,
        VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE,
        VYSMAW_MESSAGE_RDMA_READ_FAILURE,
        VYSMAW_MESSAGE_VERSION_MISMATCH,
        VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW,
        VYSMAW_MESSAGE_END

    struct message_valid_buffer:
        vysmaw_data_info info
        stddef.size_t buffer_size
        void *buffer
        uint32_t *id_num
        float complex *spectrum

    union message_content:
        message_valid_buffer valid_buffer
        vysmaw_data_info id_failure
        unsigned queue_depth
        unsigned num_data_buffers_unavailable
        unsigned num_signal_buffers_unavailable
        char signal_receive_status[VYSMAW_RECEIVE_STATUS_LENGTH]
        char rdma_read_status[VYSMAW_RECEIVE_STATUS_LENGTH]
        unsigned received_message_version
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
        const char *config_id,
        const uint8_t *stations, uint8_t baseband_index,
        uint8_t baseband_id, uint8_t spectral_window_index,
        uint8_t polarization_product_id,
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

    void vysmaw_configuration_free(vysmaw_configuration *config) nogil

    void vysmaw_shutdown(vysmaw_handle handle) nogil

    void vysmaw_message_unref(vysmaw_message *message) nogil

    vysmaw_message *vysmaw_message_queue_pop(vysmaw_message_queue queue) nogil

    vysmaw_message *vysmaw_message_queue_timeout_pop(
        vysmaw_message_queue queue,
        uint64_t timeout) nogil

    vysmaw_message *vysmaw_message_queue_try_pop(vysmaw_message_queue queue) nogil

    stddef.size_t vys_spectrum_buffer_size(
        uint16_t num_channels, uint16_t num_bins, uint16_t bin_stride) nogil

    stddef.size_t vys_spectrum_max_buffer_size(uint16_t num_channels, uint16_t num_bins) # deprecated
    stddef.size_t vys_max_spectrum_buffer_size(uint16_t num_channels, uint16_t num_bins) nogil

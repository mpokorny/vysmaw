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
from vysmaw cimport *
from libc.stdint cimport *
from libc.string cimport *
from libc.stdlib cimport *
from cpython.version cimport PY_MAJOR_VERSION
from cython cimport view
import logging
import inspect
import traceback
import warnings

def __getLogger():
    logging.basicConfig()
    return logging.getLogger(__name__)

__logger = __getLogger()

cdef void evaluate_spectrum_filter(
    const char *config_id,
    const uint8_t *stations, uint8_t baseband_index, uint8_t baseband_id,
    uint8_t spectral_window_index, uint8_t polarization_product_id,
    const vys_spectrum_info *infos, uint8_t num_infos,
    void *user_context, bool *pass_filter) with gil:
    func = <object>user_context
    try:
        func(config_id, <uint8_t[:2]>stations, baseband_index, baseband_id,
             spectral_window_index, polarization_product_id,
             <vys_spectrum_info[:num_infos]>infos,
             <bool[:num_infos]>pass_filter)
    except:
        traceback.print_exc()
    return

cdef unicode _ustring(s):
    if type(s) is unicode:
        # fast path for most common case(s)
        return <unicode>s
    elif PY_MAJOR_VERSION < 3 and isinstance(s, bytes):
        # only accept byte strings in Python 2.x, not in Py3
        return (<bytes>s).decode('ascii')
    elif isinstance(s, unicode):
        # an evil cast to <unicode> might work here in some(!) cases,
        # depending on what the further processing does.  to be safe,
        # we can always create a copy instead
        return unicode(s)
    else:
        raise TypeError

def show_properties(instance, klass):
    nv = [(name, value.__get__(instance))
          for (name, value)
          in inspect.getmembers(klass, lambda o: inspect.isdatadescriptor(o))]
    return klass.__name__ + "(" + \
        ",".join("{}={}".format(name, value) for (name, value) in nv) + ")"

cdef class Configuration:

    def __cinit__(self, path=None):
        cdef char *cpath
        apath = None
        if path is not None:
            apath = _ustring(path).encode('ascii')
            cpath = apath
        else:
            cpath = NULL
        self._c_configuration = vysmaw_configuration_new(cpath)
        if self._c_configuration is NULL:
            raise MemoryError()
        return

    def __dealloc__(self):
        if self._c_configuration is not NULL:
            vysmaw_configuration_free(self._c_configuration)
        return

    def __str__(self):
        return show_properties(self, Configuration)

    @property
    def signal_multicast_address(self):
        return (<bytes>self._c_configuration.signal_multicast_address).decode()

    @signal_multicast_address.setter
    def signal_multicast_address(self, value):
        avalue = _ustring(value).encode('ascii')
        avalue_len = len(avalue)
        max_len = sizeof(self._c_configuration.signal_multicast_address)
        if avalue_len >= max_len:
            raise ValueError("Multicast address string too long")
        strncpy(self._c_configuration.signal_multicast_address, avalue,
                avalue_len)
        self._c_configuration.signal_multicast_address[avalue_len] = b'\0'
        return

    @property
    def spectrum_buffer_pool_size(self):
        return self._c_configuration.spectrum_buffer_pool_size

    @spectrum_buffer_pool_size.setter
    def spectrum_buffer_pool_size(self, size_t value):
        self._c_configuration.spectrum_buffer_pool_size = value

    @property
    def single_spectrum_buffer_pool(self):
        return self._c_configuration.single_spectrum_buffer_pool

    @single_spectrum_buffer_pool.setter
    def single_spectrum_buffer_pool(self, bool value):
        self._c_configuration.single_spectrum_buffer_pool = value

    @property
    def max_spectrum_buffer_size(self):
        return self._c_configuration.max_spectrum_buffer_size

    @max_spectrum_buffer_size.setter
    def max_spectrum_buffer_size(self, unsigned value):
        self._c_configuration.max_spectrum_buffer_size = value

    @property
    def signal_message_receive_min_posted(self):
        return self._c_configuration.signal_message_receive_min_posted

    @signal_message_receive_min_posted.setter
    def signal_message_receive_min_posted(self, unsigned value):
        self._c_configuration.signal_message_receive_min_posted = value

    @property
    def signal_message_receive_max_posted(self):
        return self._c_configuration.signal_message_receive_max_posted

    @signal_message_receive_max_posted.setter
    def signal_message_receive_max_posted(self, unsigned value):
        self._c_configuration.signal_message_receive_max_posted = value

    @property
    def signal_message_pool_overhead_factor(self):
        return self._c_configuration.signal_message_pool_overhead_factor

    @signal_message_pool_overhead_factor.setter
    def signal_message_pool_overhead_factor(self, double value):
        self._c_configuration.signal_message_pool_overhead_factor = value

    @property
    def signal_message_receive_queue_underflow_level(self):
        return self._c_configuration.signal_message_receive_queue_underflow_level

    @signal_message_receive_queue_underflow_level.setter
    def signal_message_receive_queue_underflow_level(self, unsigned value):
        self._c_configuration.signal_message_receive_queue_underflow_level = value

    @property
    def eager_connect(self):
        return self._c_configuration.eager_connect

    @eager_connect.setter
    def eager_connect(self, bool value):
        self._c_configuration.eager_connect = value

    @property
    def eager_connect_idle_sec(self):
        return self._c_configuration.eager_connect_idle_sec

    @eager_connect_idle_sec.setter
    def eager_connect_idle_sec(self, unsigned value):
        self._c_configuration.eager_connect_idle_sec = value;

    @property
    def preconnect_backlog(self):
        return self._c_configuration.preconnect_backlog

    @preconnect_backlog.setter
    def preconnect_backlog(self, bool value):
        self._c_configuration.preconnect_backlog = value

    @property
    def message_queue_alert_depth(self):
        return self._c_configuration.message_queue_alert_depth

    @message_queue_alert_depth.setter
    def message_queue_alert_depth(self, unsigned value):
        self._c_configuration.message_queue_alert_depth = value

    @property
    def message_queue_alert_interval(self):
        return self._c_configuration.message_queue_alert_interval

    @message_queue_alert_interval.setter
    def message_queue_alert_interval(self, unsigned value):
        self._c_configuration.message_queue_alert_interval = value

    @property
    def max_starvation_latency(self):
        return self._c_configuration.max_starvation_latency

    @max_starvation_latency.setter
    def max_starvation_latency(self, unsigned value):
        self._c_configuration.max_starvation_latency = value

    @property
    def resolve_route_timeout_ms(self):
        return self._c_configuration.resolve_route_timeout_ms

    @resolve_route_timeout_ms.setter
    def resolve_route_timeout_ms(self, unsigned value):
        self._c_configuration.resolve_route_timeout_ms = value

    @property
    def resolve_addr_timeout_ms(self):
        return self._c_configuration.resolve_addr_timeout_ms

    @resolve_addr_timeout_ms.setter
    def resolve_addr_timeout_ms(self, unsigned value):
        self._c_configuration.resolve_addr_timeout_ms = value

    @property
    def inactive_server_timeout_sec(self):
        return self._c_configuration.inactive_server_timeout_sec

    @inactive_server_timeout_sec.setter
    def inactive_server_timeout_sec(self, unsigned value):
        self._c_configuration.inactive_server_timeout_sec = value

    @property
    def shutdown_check_interval_ms(self):
        return self._c_configuration.shutdown_check_interval_ms

    @shutdown_check_interval_ms.setter
    def shutdown_check_interval_ms(self, unsigned value):
        self._c_configuration.shutdown_check_interval_ms = value

    @property
    def signal_receive_min_ack_part(self):
        return self._c_configuration.signal_receive_min_ack_part

    @signal_receive_min_ack_part.setter
    def signal_receive_min_ack_part(self, unsigned value):
        self._c_configuration.signal_receive_min_ack_part = value

    @property
    def rdma_read_max_posted(self):
        return self._c_configuration.rdma_read_max_posted

    @rdma_read_max_posted.setter
    def rdma_read_max_posted(self, unsigned value):
        self._c_configuration.rdma_read_max_posted = value

    @property
    def rdma_read_min_ack_part(self):
        return self._c_configuration.rdma_read_min_ack_part

    @rdma_read_min_ack_part.setter
    def rdma_read_min_ack_part(self, unsigned value):
        self._c_configuration.rdma_read_min_ack_part = value

    cdef tuple start(self, vysmaw_spectrum_filter filtr, void *user_data):
        if filtr is NULL:
            raise ValueError("Non-null filter required to start vysmaw")
        cdef Consumer c = Consumer()
        c.set_filter(filtr, user_data)
        handle = Handle.wrap(vysmaw_start(self._c_configuration, c._c_consumer))
        return (handle, c)

    def start_py(self, filtr):
        __logger.warning("'start_py' function is for testing only, "
                         "and should not be used in production code")
        cdef Consumer c = Consumer()
        c.set_py_filter(filtr)
        handle = Handle.wrap(vysmaw_start(self._c_configuration, c._c_consumer))
        return (handle, c)

cdef class Handle:

    def __cinit__(self):
        self._c_handle = NULL
        return

    def __dealloc__(self):
        self.shutdown()
        return

    @staticmethod
    cdef Handle wrap(vysmaw_handle h):
        result = Handle()
        result._c_handle = h
        return result

    def shutdown(self):
        if self._c_handle is not NULL:
            vysmaw_shutdown(self._c_handle)
            self._c_handle = NULL
        return

cdef class Consumer:

    def __cinit__(self):
        self._c_consumer = <vysmaw_consumer *>malloc(sizeof(vysmaw_consumer))
        self._c_consumer.filter = NULL
        self._c_consumer.filter_data = NULL
        return

    def __dealloc__(self):
        self.clear()
        return

    cpdef clear(self):
        if self._c_consumer is not NULL:
            free(self._c_consumer)
            self._c_consumer = NULL
        return

    def set_py_filter(self, spectrum_filter):
        if spectrum_filter is not None:
            self._c_consumer[0].filter = evaluate_spectrum_filter
            self._c_consumer[0].filter_data = <void *>spectrum_filter
        return

    cdef void set_filter(self, vysmaw_spectrum_filter spectrum_filter,
                         void *user_data):
        if spectrum_filter is not NULL:
            self._c_consumer[0].filter = spectrum_filter
            self._c_consumer[0].filter_data = user_data
        return

    # Deprecated
    def test_end(self, message):
        warnings.warn("to be removed, without replacement",
                      warnings.DeprecationWarning)
        if isinstance(message, EndMessage):
            self.clear()

    cpdef pop(self):
        assert self._c_consumer is not NULL
        cdef vysmaw_message *msg
        with nogil:
            msg = vysmaw_message_queue_pop(self._c_consumer[0].queue)
        result = Message.wrap(msg)
        return result

    cpdef timeout_pop(self, uint64_t timeout):
        assert self._c_consumer is not NULL
        cdef vysmaw_message *msg
        with nogil:
            msg = vysmaw_message_queue_timeout_pop(
                self._c_consumer[0].queue, timeout)
        if msg is not NULL:
            result = Message.wrap(msg)
        else:
            result = None
        return result

    cpdef try_pop(self):
        assert self._c_consumer is not NULL
        cdef vysmaw_message *msg = vysmaw_message_queue_try_pop(
            self._c_consumer[0].queue)
        if msg is not NULL:
            result = Message.wrap(msg)
        else:
            result = None
        return result

    cdef vysmaw_message_queue queue(self):
        return self._c_consumer[0].queue

cdef class DataInfo:

    def __str__(self):
        return show_properties(self, DataInfo)

    @staticmethod
    cdef DataInfo wrap(vysmaw_data_info *info):
        assert info is not NULL
        result = DataInfo()
        result._c_info = info
        return result

    @property
    def id_num(self):
        return self._c_info[0].id_num

    @property
    def config_id(self):
        return self._c_info[0].config_id

    @property
    def timestamp(self):
        return self._c_info[0].timestamp

    @property
    def num_channels(self):
        return self._c_info[0].num_channels

    @property
    def num_bins(self):
        return self._c_info[0].num_bins

    @property
    def bin_stride(self):
        return self._c_info[0].bin_stride

    @property
    def stations(self):
        return <uint8_t[:2]>self._c_info[0].stations

    @property
    def baseband_index(self):
        return self._c_info[0].baseband_index

    @property
    def baseband_id(self):
        return self._c_info[0].baseband_id

    @property
    def spectral_window_index(self):
        return self._c_info[0].spectral_window_index

    @property
    def polarization_product_id(self):
        return self._c_info[0].polarization_product_id

cdef class Result:

    def __str__(self):
        return show_properties(self, Result)

    @staticmethod
    cdef Result wrap(vysmaw_result *res):
        assert res is not NULL
        result = Result()
        result._c_result = res
        return result

    @property
    def code(self):
        return <int>self._c_result[0].code

    @property
    def syserr_desc(self):
        if self._c_result[0].syserr_desc is NULL:
            return None
        desc = <bytes>self._c_result[0].syserr_desc
        return list(
            filter(
                lambda s: len(s) > 0, desc.decode('ascii').split('\n')))

cdef class Message:

    def __cinit__(self):
        return

    def __dealloc__(self):
        self.unref()
        return

    @staticmethod
    cdef Message wrap(vysmaw_message *msg):
        assert msg is not NULL
        msgtype = msg[0].typ
        if msgtype == VYSMAW_MESSAGE_SPECTRA:
            result = SpectraMessage()
        elif msgtype == VYSMAW_MESSAGE_QUEUE_ALERT:
            result = QueueAlertMessage()
        elif msgtype == VYSMAW_MESSAGE_SPECTRUM_BUFFER_STARVATION:
            result = SpectrumBufferStarvationMessage()
        elif msgtype == VYSMAW_MESSAGE_SIGNAL_BUFFER_STARVATION:
            result = SignalBufferStarvationMessage()
        elif msgtype == VYSMAW_MESSAGE_SIGNAL_RECEIVE_FAILURE:
            result = SignalReceiveFailureMessage()
        elif msgtype == VYSMAW_MESSAGE_VERSION_MISMATCH:
            result = VersionMismatchMessage()
        elif msgtype == VYSMAW_MESSAGE_SIGNAL_RECEIVE_QUEUE_UNDERFLOW:
            result = SignalReceiveQueueUnderflow()
        else: # msgtype == VYSMAW_MESSAGE_END
            result = EndMessage()
        result._c_message = msg
        return result

    cpdef unref(self):
        if self._c_message is not NULL:
            vysmaw_message_unref(self._c_message)
            self._c_message = NULL
        return

cdef class SpectraMessage(Message):

    def __cinit__(self):
        return

    def __str__(self):
        return show_properties(self, SpectraMessage)

    @property
    def info(self):
        return DataInfo.wrap(&(self._c_message[0].content.spectra.info))

    @property
    def spectrum_buffer_size(self):
        return self._c_message[0].content.spectra.spectrum_buffer_size

    @property
    def num_spectra(self):
        return self._c_message[0].content.spectra.num_spectra

    def spectrum(self, unsigned n):
        return Spectrum.get(self._c_message, n)

cdef class QueueAlertMessage(Message):

    def __str__(self):
        return show_properties(self, QueueAlertMessage)

    @property
    def queue_depth(self):
        return self._c_message[0].content.queue_depth

cdef class SpectrumBufferStarvationMessage(Message):

    def __str__(self):
        return show_properties(self, SpectrumBufferStarvationMessage)

    @property
    def num_spectrum_buffers_unavailable(self):
        return self._c_message[0].content.num_spectrum_buffers_unavailable

cdef class SignalBufferStarvationMessage(Message):

    def __str__(self):
        return show_properties(self, SignalBufferStarvationMessage)

    @property
    def num_signal_buffers_unavailable(self):
        return self._c_message[0].content.num_signal_buffers_unavailable

cdef class SignalReceiveFailureMessage(Message):

    def __str__(self):
        return show_properties(self, SignalReceiveFailureMessage)

    @property
    def signal_receive_status(self):
        return (<bytes>self._c_message[0].content.signal_receive_status).\
            decode('ascii')

cdef class VersionMismatchMessage(Message):

    def __str__(self):
        return show_properties(self, VersionMismatchMessage)

    @property
    def received_message_version(self):
        return self._c_message[0].content.received_message_version

cdef class SignalReceiveQueueUnderflow(Message):

    def __str__(self):
        return show_properties(self, SignalReceiveQueueUnderflow)

cdef class EndMessage(Message):

    def __str__(self):
        return show_properties(self, EndMessage)

    @property
    def result(self):
        cdef vysmaw_result *vr = &self._c_message[0].content.result
        return Result.wrap(vr)

cdef class Spectrum:

    def __cinit__(self):
        return

    @staticmethod
    cdef Spectrum get(vysmaw_message* msg, unsigned n):
        result = Spectrum()
        result._c_spectrum = &msg[0].data[n]
        result._length = \
            msg[0].content.spectra.spectrum_buffer_size // sizeof(float complex)
        return result


    @property
    def timestamp(self):
        return self._c_buffer[0].timestamp

    @property
    def id_failure(self):
        return self._c_buffer[0].id_failure

    @property
    def rdma_read_status(self):
        return (<bytes>self._c_buffer[0].rdma_read_status).decode('ascii')

    @property
    def values(self):
        cdef float complex[:] result = \
            <float complex[:self._length]>self._c_spectrum[0].values
        return result

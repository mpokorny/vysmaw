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

cdef class Configuration:
    cdef vysmaw_configuration *_c_configuration

    cdef tuple start(self, vysmaw_spectrum_filter filtr,
                     void *user_data)

cdef class Handle:
    cdef vysmaw_handle _c_handle

    @staticmethod
    cdef Handle wrap(vysmaw_handle h)

cdef class Consumer:
    cdef vysmaw_consumer *_c_consumer

    cpdef clear(self)

    cdef void set_filter(self, vysmaw_spectrum_filter spectrum_filter,
                         void *user_data)

    cpdef pop(self)

    cpdef timeout_pop(self, uint64_t timeout)

    cpdef try_pop(self)

    cdef vysmaw_message_queue queue(self)

cdef class DataInfo:
    cdef vysmaw_data_info *_c_info

    @staticmethod
    cdef DataInfo wrap(vysmaw_data_info *info)

cdef class Result:
    cdef vysmaw_result *_c_result

    @staticmethod
    cdef Result wrap(vysmaw_result *res)

cdef class Message:
    cdef vysmaw_message *_c_message

    @staticmethod
    cdef Message wrap(vysmaw_message *msg)

    cpdef unref(self)

cdef class Spectrum:
    cdef vysmaw_spectrum *_c_spectrum

    cdef unsigned _length

    @staticmethod
    cdef Spectrum get(vysmaw_message *msg, unsigned n)

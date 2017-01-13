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
from libc.stdlib cimport *
from cy_vysmaw cimport *
import cy_vysmaw
import sys

# A predicate that selects no spectra. The "pass_filter" array elements _must_
# be assigned values, as they are always uninitialized at function entry.
cdef void cb(const uint8_t *stns, uint8_t spw, uint8_t sto, 
             const vys_spectrum_info *infos, uint8_t num_infos,
             void *user_data, bool *pass_filter) nogil:
    for i in range(num_infos):
        pass_filter[i] = False
    return

# Use configuration file if provided on command line, otherwise use defaults.
cdef Configuration config
if len(sys.argv) > 1:
    config = cy_vysmaw.Configuration(sys.argv[1])
else:
    config = cy_vysmaw.Configuration()

# Allocate client resources
cdef vysmaw_spectrum_filter *f = \
    <vysmaw_spectrum_filter *>malloc(sizeof(vysmaw_spectrum_filter))
f[0] = cb
handle, consumers = config.start(1, f, NULL)

# Immediately shut down client resources, since we don't intend to receive
# any spectra.
handle.shutdown()

# Messages should always be retrieved from the consumer queue until an
# EndMessage appears; here, since no spectra are selected by the callback,
# and the handle shutdown method has already been called, the only message
# should be the EndMessage.
msg = consumers[0].pop()
assert(isinstance(msg, cy_vysmaw.EndMessage))

# display the message
print(str(msg))

# unref the message; this would happen automatically when the msg variable
# is reclaimed, but it's good practice to do this explicitly with every
# message as soon as possible.
msg.unref()

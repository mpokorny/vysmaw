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
import cy_vysmaw
import sys
from cython.parallel import parallel

######
#
# NOTE: this application is broken. There appears to be something wrong in how
# the callback function is being called by
# cy_vysmaw.evaluate_spectrum_filter(). The result is that an exception,
# "ValueError: Expected 1 dimension(s), got 1" is thrown whenever the callback
# is invoked.
#
#####

# A predicate that selects no spectra. The "pass_filter" array elements _must_
# be assigned values, as they are always uninitialized at function entry.
def cb(char [:] config, uint8_t[:] stns, uint8_t bb_idx, uint8_t bb_id,
       uint8_t spw, uint8_t pol, vys_spectrum_info[:] infos, bool[:] pass_filter):
    for i in range(pass_filter.shape[0]):
        pass_filter[i] = False
    return

# Use configuration file if provided on command line, otherwise use defaults.
if len(sys.argv) > 1:
    config = cy_vysmaw.Configuration(sys.argv[1])
else:
    config = cy_vysmaw.Configuration()
    # Use default configuration

# Allocate client resources
handle, consumers = config.start_py([cb])

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

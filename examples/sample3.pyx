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
from cpython cimport PyErr_CheckSignals
import cy_vysmaw
import signal
import sys

cdef unsigned long num_cbs = 0
DEF on_period = 1000000uLL
DEF full_period = 4 * on_period

# A predicate that selects spectra depending only on their timestamps. The
# user_data argument is used to count the number of times the callback is
# called.
cdef void cb(const char *config_id, const uint8_t *stns,
             uint8_t bb_idx, uint8_t bb_id, uint8_t spw, uint8_t pol,
             const vys_spectrum_info *infos, uint8_t num_infos,
             void *user_data, bool *pass_filter) nogil:
    cdef unsigned long *ncb = <unsigned long *>user_data
    for i in range(num_infos):
        pass_filter[i] = (infos[i].timestamp % full_period) / on_period == 0
    ncb[0] += 1
    return

# Use configuration file if provided on command line, otherwise use defaults.
cdef Configuration config
if len(sys.argv) > 1:
    config = cy_vysmaw.Configuration(sys.argv[1])
else:
    config = cy_vysmaw.Configuration()

# keep track of number of spectra received
num_spectra = 0

# set up signal handler to quit on SIGINT
interrupted = False
def interrupt(sig, frame):
    global interrupted
    interrupted = True
    return
signal.signal(signal.SIGINT, interrupt)

# start vysmaw client
cdef tuple hc = config.start(cb, &num_cbs)
handle = hc[0]
cdef Consumer consumer = hc[1]

# For maximum efficiency, one should work directly with unwrapped messages to
# avoid allocating a Python object for every message. Doing so requires direct
# access to the queue referenced by the consumer.
cdef vysmaw_message_queue queue = consumer.queue()

# Messages should always be retrieved from the consumer queue until an
# EndMessage appears. A NULL-valued msg can appear here due to using a timeout
# in getting a message from the queue in order to allow for interrupt handling.
cdef vysmaw_message *msg = NULL
while msg is NULL or msg[0].typ is not VYSMAW_MESSAGE_END:
    if msg is not NULL:
        if msg[0].typ is VYSMAW_MESSAGE_BUFFERS:
            num_spectra += 1
        # for other message types, which should be received much less frequently
        # than the "valid buffer" messages, it could be convenient at this stage
        # to wrap them in Python objects, like so: py_msg = Message.wrap(msg)

        # must unref (unwrapped) vysmaw_messages explicitly, since Python
        # reclamation won't do it for us [N.B. use only one of
        # vysmaw_message_unref() or a Python wrappped messages's unref()
        # method.]
        vysmaw_message_unref(msg)

    if interrupted:
        if handle is not None:
            handle.shutdown()
            # handle is now invalid, so let's not use it again
            handle = None
        interrupted = False
    msg = vysmaw_message_queue_timeout_pop(queue, 500000)
    # Must call PyErr_CheckSignals() for Python signal handling to occur. This
    # is a sign that this 'while' loop compiles to C, and never enters the
    # Python interpreter. [If a call to print() is added anywhere in this loop,
    # the PyErr_CheckSignals call becomes unnecessary.]
    PyErr_CheckSignals()

# show the end message
py_msg = Message.wrap(msg) # this steals the message reference
print(str(py_msg))
py_msg.unref()

# Call the handle's shutdown method (although reclamation of the Python handle
# object would take care of it otherwise)
if handle is not None:
    handle.shutdown()

# display the message
print("{} callbacks, {} spectra".format(num_cbs, num_spectra))

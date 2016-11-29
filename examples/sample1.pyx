from vysmaw cimport *
from libc.stdint cimport *
import cy_vysmaw

# A predicate that selects no spectra. The "pass_filter" array elements _must_
# be assigned values, as they are always uninitialized at function entry.
def cb(uint8_t[:] stns, uint8_t spw, uint8_t sto, 
       vysmaw_spectrum_info[:] infos, bint[:] pass_filter):
    for i in xrange(pass_filter.shape[0]):
        pass_filter[i] = False
    return

# Use default configuration
config = cy_vysmaw.Configuration()

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

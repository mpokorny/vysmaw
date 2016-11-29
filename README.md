# vysmaw client library

**maw** /mȯ/
  _noun_
  * the jaws or throat of a voracious animal

**vys·maw** /'vizmȯ/
  _noun_
  * a library for receiving a fast stream of visbility data

The vysmaw client library is intended to facilitate the development of code for
processes to tap into the fast visibility stream on the National Radio
Astronomy's Very Large Array correlator back-end InfiniBand network. Please be
aware that this library, as well as the implementation of the fast visibility
stream at the VLA, is experimental in nature.

## Build dependencies

  * cmake, version 2.8 or later
  * gcc, tested on version 5.x and 6.1.0; other C compilers may work
  * libibverbs, OFED version 1.1.8 or later?
  * librdmacm, OFED version 1.1.8 or later?
  * glib-2.0, version 2.28 or later
  * Python, version 2.7 or later (including 3.x)
  * cython, version 0.24 or later

The above dependencies must be satisfied with "development" versions of
packages, where applicable.

The version numbers quoted above reflect those used in development so far; they
are subject to change, and may or may not correspond to strict version
requirements. If you successfully build this project, please send a note to the
repository owner with the versions of the above dependencies you used.

## Build instructions

Simple: run cmake, followed by make. Below are some cmake scripts that I've used
for development on two different systems to help get you started.

A debug build on a standard NRAO RHEL 6.6 machine, with a locally installed,
modern version of cmake:

``` shell
GCC=/opt/local/compilers/gcc-6/bin/gcc
PYTHON_EXECUTABLE=$( python-config --prefix )/bin/python
PYTHON_LIBRARY=$( ls $( python-config --prefix )/lib/libpython*.so )
PYTHON_INCLUDE_DIR=$( ls -d $( python-config --prefix )/include/python* )

CMAKE="~/stow/cmake-3.6.3/bin/cmake -DCMAKE_BUILD_TYPE=Debug \
 -DCMAKE_C_COMPILER=$GCC -DPYTHON_EXECUTABLE=$PYTHON_EXECUTABLE \
 -DPYTHON_LIBRARY=$PYTHON_LIBRARY -DPYTHON_INCLUDE_DIR=$PYTHON_INCLUDE_DIR .."
echo $CMAKE
eval $CMAKE
```

A release build on a Ubuntu 16.10 machine:

``` shell
GCC=$( which gcc )
PYTHON_EXECUTABLE=$( which python3 )
PYTHON_LIBRARY=/usr/lib/x86_64-linux-gnu/libpython3.5m.so.1.0
PYTHON_INCLUDE_DIR=/usr/include/python3.5m

CMAKE="cmake -DCMAKE_C_COMPILER=$GCC \
 -DPYTHON_EXECUTABLE=$PYTHON_EXECUTABLE -DPYTHON_LIBRARY=$PYTHON_LIBRARY \
 -DPYTHON_INCLUDE_DIR=$PYTHON_INCLUDE_DIR .."
echo $CMAKE
eval $CMAKE
```

I recommend building the project in a sub-directory of the top level project
directory. This allows one to easily remove all build artifacts, including the
cmake generated files, quite easily.

``` shell
# from the top level project directory...
mkdir build
cd build
cmake .. # replace with your cmake command
```

## Build artifacts

The two primary artifacts produced by the build are a C language shared library,
and a Python extension with a Python/Cython interface to the shared library.

Note that there is no "install" make target yet. If you intend to build and run
sample code, you may have to set PYTHONPATH to point to the vysmaw/py
sub-directory of the build directory.

## Interfaces

### C API

At the moment, the API for the C language library is detailed in the vysmaw.h
source file. Python programmers are encouraged to refer the comments in that
file for documentation, as well.

### Python/Cython API

A complete API is available in Python, although production code should resort to
the Cython interface in some circumstances. In particular, for performance
reasons, the callback provided by the client, which is used to decide which
spectra are of interest to the client, ought to be implemented in Cython (or C).
The callback will be called very frequently by the client library under most
conditions; therefore, the callback is executed without locking the Python GIL,
and the callback itself should preferably **not** lock the GIL. Using an
inefficient callback will result in the client not receiving all the spectra
that it wishes to receive (although such a callback will not affect other
clients, or the correlator back-end.)

## Usage

Every client that initializes the library receives upon return from the
initialization function a vysmaw client handle, representing the resources
allocated by the library for that client, and a visibility data queue reference.
Upon initialization, a client provides the library with a callback function
predicate that is used by the library to determine the visibility spectra that
are to be delivered to the client _via_ the visibility data queue. Only those
spectra that satisfy the predicate will be passed to the client on the data
queue it receives after initialization. After initialization, the client must
simply take items (_i.e._, spectra) from the queue repeatedly, eventually
calling a shutdown function, and continuing to take items from the queue until a
special, sentinel value is retrieved. For efficiency in the library
implementation, the memory used to store spectra is, as described below, a
limited resource, which requires that client applications make an effort to
release references to spectral data as soon as possible. Failure to release
spectral data references in the client application may result in failures of the
client to receive all the spectra that it is expected.

## vysmaw implementation

This section is intended to provide insight into the implementation of the
vysmaw system for vysmaw client application authors, but is not necessary to
successfully write vysmaw client applications.

The "wcbe" application is a distributed application running on the VLA CBE
cluster, which receives and processes the various WIDAR data products according
to the requirements of each WIDAR configuration, and eventually writes
visibility data to BDF files. The mapping of WIDAR data products to wcbe
processes may change with every WIDAR reconfiguration according to the number of
active sub-arrays, the CBE nodes that are in active use, and an opaque WIDAR
product-to-CBE mapping algorithm implemented by wcbe. The vysmaw system operates
_via_ a broadcast by wcbe of spectral metadata to clients as the data are being
processed by each wcbe process, allowing clients to receive data from any CBE
process without prior knowledge of the mapping of WIDAR products to CBE
processes. These broadcast messages provide sufficient metadata to identify not
only the identity of the visibility spectrum, but also the "location" of the
spectrum in the CBE. Clients may then retrieve only those spectra which they
require.

The current vysmaw implementation is based on OpenFabrics Enterprise
Distribution (OFED)/OpenFabrics Software (OFS), which provides access to RDMA
(Remote Direct Memory Access) and kernel bypass send/receive features of the
InfiniBand fabric used by the CBE cluster. Both the metadata broadcast and
spectrum retrieval functions described in the preceding paragraph are
implemented using features of OFS. The use of these OFS features allows for
efficient transfer of data over the fabric directly to the client library and
application, but at the cost of requiring the active participation of the
application in managing the resources used by the client library. This design
nevertheless does not create any direct dependencies between vysmaw clients or
between clients and the wcbe processes, which allows for a high level of
isolation between all processes in the vysmaw system. In other words, failure of
a client process to manage resources efficiently can only affect the data
received by that process. Any dependencies that exist will only be at the level
of system resource limitations; for example, two vysmaw clients running on a
single node must share the available memory on that node (while the address
spaces of the client processes remain distinct.)

The most significant of the resources allocated by the vysmaw library for every
client is so-called "registered memory." Registered memory is used by OFS
routines to allow communication over OpenFabrics networks to bypass the
operating system kernel, which is a key feature of its performance. All OFS
send/receive and RDMA read/write operations require access to registered memory.
Registered memory takes the form of physical memory locked in the virtual
address space of the kernel. For highest performance, the vysmaw library does
_not_ copy data out of registered memory buffers prior to providing the client
access to such buffers. The accounting of registered memory usage by a vysmaw
client is handled by the library itself, although this requires the
participation of the client application to notify the library when the
application has finished accessing the contents of a buffer in registered
memory in some cases.

### metadata broadcast

The spectrum metadata are received by the vysmaw client library in a registered
memory block. Access to these metadata are provided to the client application
through the callback function predicate arguments. Although the client is not
required to explicitly release a reference to every buffer used for the
metadata, it is nevertheless possible for the application to cause in the
library the starvation of buffers available to receive the metadata messages.
Although there is buffering between the metadata receive loop in vysmaw and the
call to the client callback function (to minimize latency in the network
communication loop), an inefficient callback may result in the receive loop
running out of buffers into which to write the received metadata messages.

Note that the client callback function signature is designed for some amount of
batch processing by the function. This design not only allows the library to
invoke the callback less frequently than otherwise possible, but it is also
aligned with the batching of metadata in the messages from the wcbe processes.

The broadcast of spectrum metadata to vysmaw clients is currently implemented
using multicast over InfiniBand. Although this implementation may change if the
performance proves to be inadequate, the implications for client application
authors should be unaffected by any such change.

### spectral data

All spectra whose metadata satisfy the client callback predicate are retrieved
by the vysmaw library _via_ OFS RDMA into a registered memory block. These
buffers are provided directly to the client application in the messages the
client retrieves from the queue. To minimize the risk of causing starvation of
buffers for receiving spectral data in the vysmaw library, clients should
release the buffers referenced in the messages received on the queue as soon as
possible. This generally means that the data should be read from the buffer by
the client application code at most one time. A buffer is released by calling
the "unref" function for the message (which must be done for every message,
regardless of its type, but for reasons other than to avoid depletion of the
available registered memory.) Note a Message in the Cython layer will
automatically release its reference to the underlying C-level message when its
Python reference count goes to zero, although it is good practice to call the
"unref" function explicitly in client code to ensure the buffer is returned to
the registered memory pool as soon as possible.

### spectral data availability

The spectral data in the CBE are maintained at the location indicated in the
metadata broadcasts for a limited time. On the CBE side, the spectral data
available to vysmaw are also required to be in registered memory, which is used
for spectral data buffers on a rotating basis. Every spectrum for which metadata
are broadcast will be available for reading from vysmaw client processes for a
limited time. Each spectral data buffer hosted by some CBE process will
eventually be reused by that process for other data. The length of time for
which a spectrum is available is dependent upon the WIDAR dump rate for the
product, and the amount of memory allocated by the CBE processes to contain
spectral data buffers. At this time, a minimum value for the time that any
spectral data buffer will be valid is undetermined, although, given the current
CBE configuration, about two seconds is reasonable. The protocol used by the
vysmaw system includes a data validation step to ensure that the data received
by a vysmaw client is that matching the metadata used to identify the spectrum.
To be clear, once a data product spectrum has been read by a client, it exists
in the client's physical memory, and cannot be overwritten until the client
releases the buffer reference. The difference in time from when a CBE process
sends a metadata broadcast for a given spectral data product to the time that a
client has read the spectral data is the critical quantity in determining
whether the spectral data is valid when it is received by the client. When that
time difference increases, the likelihood that the spectral data will valid when
they arrive in the client's memory decreases.

## Sample code

All sample code can be found under the "examples" project directory.

### sample1

This application is trivial in that it uses a callback that selects no
spectra. It will run to completion on any machine, even in the absence of an
InfiniBand HCA. The application will simply print the end-of-data-stream message
to stdout, since no spectra are selected.

If there is no InfiniBand HCA, the library will immediately signal the end of
the data stream, and provide error messages to the client in the
end-of-data-stream message. Also, the OFS software insists on printing messages
to stderr if no InifiniBand HCA is present, but these can be suppressed by
redirecting stderr to /dev/null.

``` cython
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
```

Note that the above uses the start_py method, which is convenient for
development and testing, but is not recommended for production code.

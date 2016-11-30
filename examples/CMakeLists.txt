project(examples)

cmake_policy(SET CMP0015 NEW)
cmake_policy(SET CMP0057 NEW)

include(UseCython)
include(FindPythonExtensions)

find_package(Cython)

include_directories(../py ../src)
link_directories(../py ../src)

add_cython_target(sample1 EMBED_MAIN)
add_executable(sample1 ${sample1})
python_standalone_executable(sample1)

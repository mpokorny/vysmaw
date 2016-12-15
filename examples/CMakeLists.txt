cmake_policy(SET CMP0015 NEW)
cmake_policy(SET CMP0057 NEW)

include(UseCython)
include(FindPythonExtensions)

find_package(Cython)
set(CYTHON_FLAGS -I../../py -I../../src)

include_directories(../src)
link_directories(../py ../src)

add_cython_target(sample1 EMBED_MAIN)
add_executable(sample1 ${sample1})
python_standalone_executable(sample1)

add_cython_target(sample2 EMBED_MAIN)
add_executable(sample2 ${sample2})
python_standalone_executable(sample2)

add_cython_target(sample3 EMBED_MAIN)
add_executable(sample3 ${sample3})
target_link_libraries(sample3 vysmaw)
python_standalone_executable(sample3)

add_executable(sample4 sample4.cc)
target_link_libraries(sample4 vysmaw)
target_compile_options(sample4 PRIVATE
  -Wall -Werror)
set_target_properties(sample4 PROPERTIES
  LINK_FLAGS -static-libstdc++)

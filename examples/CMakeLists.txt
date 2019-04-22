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
target_link_libraries(sample1 vysmaw)
python_standalone_executable(sample1)

add_cython_target(sample2 EMBED_MAIN)
add_executable(sample2 ${sample2})
target_link_libraries(sample2 vysmaw)
python_standalone_executable(sample2)

add_cython_target(sample3 EMBED_MAIN)
add_executable(sample3 ${sample3})
target_link_libraries(sample3 vysmaw)
python_standalone_executable(sample3)

add_executable(sample4 sample4.cc)
target_link_libraries(sample4 vysmaw)
target_compile_options(sample4 PRIVATE
  -Wall -Werror)

add_executable(sample5 sample5.cc)
target_link_libraries(sample5 vysmaw)
target_compile_options(sample5 PRIVATE
  -Wall -Werror)
set_target_properties(sample5 PROPERTIES
  LINK_FLAGS -static-libstdc++)

add_executable(sample6 sample6.cc)
target_link_libraries(sample6 vysmaw)
target_compile_options(sample6 PRIVATE
  -Wall -Werror)
set_target_properties(sample6 PROPERTIES
  LINK_FLAGS -static-libstdc++)

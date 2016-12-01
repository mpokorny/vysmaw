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

add_cython_target(sample2 EMBED_MAIN)
add_executable(sample2 ${sample2})
python_standalone_executable(sample2)

add_cython_target(sample3 EMBED_MAIN)
add_executable(sample3 ${sample3})
target_link_libraries(sample3 vysmaw)
python_standalone_executable(sample3)

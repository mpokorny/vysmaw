cmake_policy(SET CMP0015 NEW)
cmake_policy(SET CMP0057 NEW)

include(UseCython)
include(FindPythonExtensions)

find_package(Cython)
add_cython_target(cy_vysmaw cy_vysmaw.pyx)

include_directories(${PYTHON_INCLUDE_DIRS} ../src)
link_directories(../src)
add_library(cy_vysmaw MODULE ${cy_vysmaw})
target_link_libraries(cy_vysmaw vysmaw)
python_extension_module(cy_vysmaw)
target_compile_options(cy_vysmaw PRIVATE
  -fno-short-enums)

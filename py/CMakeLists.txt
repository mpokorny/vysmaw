cmake_policy(SET CMP0015 NEW)
cmake_policy(SET CMP0057 NEW)

include(UseCython)
include(FindPythonExtensions)

# use, i.e. don't skip the full RPATH for the build tree
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# when building, don't use the install RPATH already (but later on when
# installing)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# add the automatically determined parts of the RPATH which point to directories
# outside the build tree to the install RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
  "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif("${isSystemDir}" STREQUAL "-1")

find_package(Cython)
set(CYTHON_FLAGS -I../../py -I../../src)
add_cython_target(cy_vysmaw cy_vysmaw.pyx)

include_directories(${PYTHON_INCLUDE_DIRS} ../src)
link_directories(../src)
add_library(cy_vysmaw MODULE ${cy_vysmaw})
target_link_libraries(cy_vysmaw vysmaw)
python_extension_module(cy_vysmaw)
target_compile_options(cy_vysmaw PRIVATE
  -fno-short-enums)

execute_process(
  COMMAND "${PYTHON_EXECUTABLE}" -c "if True:
    import sysconfig as sc
    print(sc.get_path('platlib'))"
  OUTPUT_VARIABLE PYTHON_SITE
  OUTPUT_STRIP_TRAILING_WHITESPACE)

install(
  TARGETS cy_vysmaw
  LIBRARY DESTINATION ${PYTHON_SITE}/vysmaw
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE
              GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(
  FILES __init__.py cy_vysmaw.pxd vysmaw.pxd
  DESTINATION ${PYTHON_SITE}/vysmaw
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

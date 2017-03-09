cmake_policy(SET CMP0015 NEW)

find_package(MPI REQUIRED)
find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)

# use, i.e. don't skip, the full RPATH for the build tree
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

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -Wall -Werror")

add_executable(vyssim
  vyssim.c)
target_include_directories(vyssim PRIVATE
  ${MPI_C_INCLUDE_PATH}
  ${GTHREAD2_INCLUDE_DIRS}
  ../src)
target_compile_options(vyssim PRIVATE
  ${MPI_C_COMPILE_FLAGS}
  ${GTHREAD2_CFLAGS}
  ${GTHREAD2_CFLAGS_OTHER})
target_link_libraries(vyssim
  ${MPI_C_LIBRARIES}
  ${GTHREAD2_LIBRARIES}
  ${VERBS_LIBRARY}
  ${RDMACM_LIBRARY}
  vys)
install(TARGETS vyssim
  RUNTIME DESTINATION bin
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

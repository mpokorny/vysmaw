find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -Wall -Werror")

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

# vys library
add_library(vys SHARED
  vys_private.c
  vys.c)
target_include_directories(vys PRIVATE
  ${GLIB2_INCLUDE_DIRS}
  .)
target_compile_options(vys PRIVATE
  ${GLIB2_CFLAGS}
  ${GLIB2_CFLAGS_OTHER})
target_compile_definitions(vys PRIVATE
  VYS_CONFIG_PATH="${CMAKE_INSTALL_PREFIX}/etc/vys.conf"
  VYS_SIGNAL_MULTICAST_ADDRESS="224.0.0.100")
target_link_libraries(vys
  ${GLIB2_LIBRARIES})

# vysmaw library
add_library(vysmaw SHARED
  vysmaw_private.c
  buffer_pool.c
  signal_receiver.c
  spectrum_selector.c
  spectrum_reader.c
  async_queue.c
  vysmaw.c)
target_include_directories(vysmaw PRIVATE
  ${GTHREAD2_INCLUDE_DIRS}
  .)
target_compile_options(vysmaw PRIVATE
  ${GTHREAD2_CFLAGS}
  ${GTHREAD2_CFLAGS_OTHER})
target_compile_definitions(vysmaw PRIVATE
  VYSMAW_CONFIG_PATH="${CMAKE_INSTALL_PREFIX}/etc/vysmaw.conf")
target_link_libraries(vysmaw
  vys
  ${GTHREAD2_LIBRARIES}
  ${VERBS_LIBRARY}
  ${RDMACM_LIBRARY})

# install rules

install(TARGETS vys vysmaw
  LIBRARY DESTINATION lib
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES vys.h vysmaw.h
  DESTINATION include
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
install(FILES vys.conf vysmaw.conf
  DESTINATION etc
  CONFIGURATIONS Release
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ WORLD_READ)

cmake_minimum_required(VERSION 2.8)

project(vysmaw)
set(vysmaw_VERSION_MAJOR 0)
set(vysmaw_VERSION_MINOR 1)

find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)

add_library(vysmaw SHARED
  vysmaw_private.c
  buffer_pool.c
  signal_receiver.c
  spectrum_selector.c
  spectrum_reader.c
  vysmaw.c)

include_directories(
  ${GTHREAD2_INCLUDE_DIRS}
  ${VERBS_INCLUDE_DIR}
  ${RDMACM_INCLUDE_DIR}
  .)
add_compile_options(-Wall ${GTHREAD2_CFLAGS})
link_directories(${GTHREAD2_LIBRARY_DIRS})
target_link_libraries(
  vysmaw
  ${GTHREAD2_LIBRARIES}
  ${VERBS_LIBRARY}
  ${RDMACM_LIBRARY})

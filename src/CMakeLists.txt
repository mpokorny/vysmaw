find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -Wall -Werror")

add_library(vysmaw SHARED
  vysmaw_private.c
  buffer_pool.c
  signal_receiver.c
  spectrum_selector.c
  spectrum_reader.c
  vysmaw.c)

include_directories(
  ${GTHREAD2_INCLUDE_DIRS}
  .)
add_compile_options(
  ${GTHREAD2_CFLAGS}
  ${GTHREAD2_CLFAGS_OTHER})

target_link_libraries(
  vysmaw
  ${GTHREAD2_LIBRARIES}
  ${VERBS_LIBRARY}
  ${RDMACM_LIBRARY})

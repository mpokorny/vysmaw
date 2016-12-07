cmake_policy(SET CMP0015 NEW)

find_package(MPI REQUIRED)
find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -Wall -Werror")

add_executable(vyssim
  ../src/buffer_pool.c
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

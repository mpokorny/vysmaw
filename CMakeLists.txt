cmake_minimum_required(VERSION 2.8)

project(vysmaw)
set(vysmaw_VERSION_MAJOR 0)
set(vysmaw_VERSION_MINOR 1)

set(
  CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_LIST_DIR}/cmake/Modules)

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -fno-short-enums")

set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -fno-short-enums")

add_subdirectory(src)
add_subdirectory(py)
add_subdirectory(examples)
add_subdirectory(vyssim)

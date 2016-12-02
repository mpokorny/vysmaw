cmake_minimum_required(VERSION 2.8)

project(vysmaw)
set(vysmaw_VERSION_MAJOR 0)
set(vysmaw_VERSION_MINOR 1)

set(
  CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_LIST_DIR}/cmake/Modules)

add_subdirectory(src)
add_subdirectory(py)
add_subdirectory(examples)
add_subdirectory(vyssim)

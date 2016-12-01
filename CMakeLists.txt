cmake_minimum_required(VERSION 2.8)

set(
  CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_LIST_DIR}/cmake/Modules)

add_subdirectory(src)
add_subdirectory(py)
add_subdirectory(examples)

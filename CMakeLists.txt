cmake_minimum_required(VERSION 2.8)

set(
  CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_LIST_DIR}/cmake/Modules)

find_package(Verbs REQUIRED)
find_package(RDMACM REQUIRED)

add_subdirectory(src)
add_subdirectory(py)
add_subdirectory(examples)

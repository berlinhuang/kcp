cmake_minimum_required(VERSION 3.8)
project(kcp)

set(CMAKE_CXX_STANDARD 11)


add_library(ikcp ikcp.c)
add_executable(testkcp test.cpp)
target_link_libraries(testkcp ikcp)


add_executable(iqueuehead iqueuehead.cpp)
target_link_libraries(iqueuehead ikcp)
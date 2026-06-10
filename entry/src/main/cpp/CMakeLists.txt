cmake_minimum_required(VERSION 3.4.0)
project(udp_socket_napi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

add_library(udp_socket SHARED udp_socket.cpp)
target_link_libraries(udp_socket PUBLIC ace_napi.z)

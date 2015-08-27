cmake_minimum_required(VERSION 2.8)
project(libcryptosec)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})
add_subdirectory(src)

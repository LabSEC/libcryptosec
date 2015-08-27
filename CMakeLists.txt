cmake_minimum_required(VERSION 2.8)
project(libcryptosec)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
find_package(OpenSSL REQUIRED)
find_package(LibP11 REQUIRED)

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${LIBP11_INCLUDE_DIR})
add_subdirectory(src)
add_subdirectory(tests)

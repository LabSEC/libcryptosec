cmake_minimum_required(VERSION 2.8)
project(libcryptosec)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES)

include_directories(include)
add_subdirectory(src)

add_library(cryptosec)
target_link_libraries(cryptosec src)

install(TARGETS cryptosec
        DESTINATION lib)

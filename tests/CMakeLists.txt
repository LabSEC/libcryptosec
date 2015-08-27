cmake_minimum_required(VERSION 2.8)

include_directories(gtest)
add_subdirectory(src)

add_test(alltests testing)

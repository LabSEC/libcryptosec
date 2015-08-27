cmake_minimum_required(VERSION 2.8)

set(SOURCE_FILES
        BrainpoolEcTest.cpp
        HmacTest.cpp
        Main.cpp)

add_executable(testing ${SOURCE_FILES})
target_link_libraries(testing gtest cryptosec)

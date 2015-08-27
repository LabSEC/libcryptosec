cmake_minimum_required(VERSION 2.8)

set(SOURCE_FILES
        BrainpoolEcTest.cpp
        HmacTest.cpp
        Main.cpp)

find_package(GTest REQUIRED)
include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR} ${GTEST_INCLUDE_DIRS})

add_executable(BrainpoolTest BrainpoolEcTest.cpp Main.cpp)
add_executable(HmacTest HmacTest.cpp Main.cpp)
target_link_libraries(BrainpoolTest cryptosec ${CMAKE_THREAD_LIBS_INIT} ${GTEST_BOTH_LIBRARIES})
target_link_libraries(HmacTest cryptosec ${CMAKE_THREAD_LIBS_INIT} ${GTEST_BOTH_LIBRARIES})
add_test(BrainpoolTest BrainpoolTest)
add_test(HmacTest HmacTest)

file(COPY files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

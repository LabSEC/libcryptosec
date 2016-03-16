cmake_minimum_required(VERSION 2.8)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libcryptosec DESTINATION include
        FILES_MATCHING PATTERN "*.h")

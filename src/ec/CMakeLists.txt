cmake_minimum_required(VERSION 2.8)

set(SOURCE_FILES
        BrainpoolCurveFactory.cpp
        EllipticCurve.cpp)

add_library(ec ${SOURCE_FILES})

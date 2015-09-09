cmake_minimum_required(VERSION 2.8)

set(SOURCE_FILES
        Asn1Attribute.cpp
        Asn1BitString.cpp
        Asn1Boolean.cpp
        Asn1Enumerated.cpp
        Asn1Integer.cpp
        Asn1Object.cpp
        Asn1Sequence.cpp
        Asn1Type.cpp)

add_library(asn1 ${SOURCE_FILES})

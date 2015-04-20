cmake_minimum_required(VERSION 2.8.3)
project(SimpleMallocTrace)

SET (SOURCE
    smtest.cpp
    SimpleMallocTrace.cpp
    Symbolize.h
    Symbolize.cpp
    Demangle.h
    Demangle.cpp
)

ADD_DEFINITIONS(-g)

LINK_LIBRARIES(pthread dl)

ADD_EXECUTABLE(smtest ${SOURCE})

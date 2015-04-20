cmake_minimum_required(VERSION 2.8.3)
project(SimpleMallocTrace)

SET (SOURCE
    smtest.cpp
    simplemtrace.cpp
    Symbolize.h
    Symbolize.cpp
    Demangle.h
    Demangle.cpp
)

LINK_LIBRARIES(pthread dl)

ADD_EXECUTABLE(smtest ${SOURCE})

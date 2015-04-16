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

macro(findNameofLIBC)
    FILE(WRITE ${CMAKE_CURRENT_BINARY_DIR}/a.c "void main(){}")
    EXECUTE_PROCESS(COMMAND cc -o ${CMAKE_CURRENT_BINARY_DIR}/a.out ${CMAKE_CURRENT_BINARY_DIR}/a.c)
    EXECUTE_PROCESS(COMMAND ldd ${CMAKE_CURRENT_BINARY_DIR}/a.out
                    COMMAND awk "/libc/{printf $3}"
                    OUTPUT_VARIABLE NAMEOFLIBC)
    MESSAGE(${NAMEOFLIBC})
    EXECUTE_PROCESS(COMMAND rm ${CMAKE_CURRENT_BINARY_DIR}/a.c ${CMAKE_CURRENT_BINARY_DIR}/a.out)
endmacro()

findNameofLIBC()

ADD_DEFINITIONS(-DNAME_OF_LIBC="${NAMEOFLIBC}")

LINK_LIBRARIES(pthread dl)

ADD_EXECUTABLE(smtest ${SOURCE})

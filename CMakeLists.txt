project(meaps C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O0 -D_GNU_SOURCE")
include_directories(picohttp)
set(SRCS
    meaps.c
    picohttp/picohttpparser.c)
add_executable(meaps ${SRCS})

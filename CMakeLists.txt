project(meaps C)
cmake_minimum_required(VERSION 2.8)

find_package(OpenSSL)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O0 -D_GNU_SOURCE")
include_directories(include picohttp ${OPENSSL_INCLUDE_DIR})
set(SRCS
    lib/meaps.c
    lib/meaps_ssl.c
    picohttp/picohttpparser.c)
add_library(meaps ${SRCS})
target_link_libraries(meaps ${OPENSSL_LIBRARIES})

add_executable(single src/single.c)
target_link_libraries(single meaps)

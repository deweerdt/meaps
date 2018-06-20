project(meaps C)
cmake_minimum_required(VERSION 2.8)

find_package(OpenSSL)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O0 -D_GNU_SOURCE")
include_directories(picohttp ${OPENSSL_INCLUDE_DIR})
set(SRCS
    meaps.c
    meaps_ssl.c
    picohttp/picohttpparser.c)
add_executable(meaps ${SRCS})
target_link_libraries(meaps ${OPENSSL_LIBRARIES})

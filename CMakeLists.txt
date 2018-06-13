project(meaps C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2 -D_GNU_SOURCE")
set(SRCS meaps.c)
add_executable(meaps ${SRCS})

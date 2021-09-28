cmake_minimum_required(VERSION 3.20)
project(PKS_Z1 C)

set(CMAKE_C_STANDARD 99)

include(FindPCAP.cmake)

set(SOURCE_FILES main.c)

add_executable(PKS_Z1 ${SOURCE_FILES})
target_link_libraries(PKS_Z1 ${PCAP_LIBRARY})



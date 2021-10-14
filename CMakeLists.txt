cmake_minimum_required(VERSION 3.20)
project(PKS_Zadanie1_linux C)

set(CMAKE_C_STANDARD 99)

include(FindPCAP.cmake)

set(SOURCE_FILES main.c)

add_executable(PKS_Zadanie1_linux ${SOURCE_FILES})
target_link_libraries(PKS_Zadanie1_linux ${PCAP_LIBRARY})



cmake_policy(SET CMP0048 NEW)
project(ping VERSION 1.1)

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

add_executable(ping
    ping.c
)

find_package(Threads REQUIRED)

#target_compile_options(ping PRIVATE -fsanitize=address -g)
#target_link_options(ping PRIVATE -fsanitize=address)

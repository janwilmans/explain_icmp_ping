project(ping)

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

add_executable(ping
    ping.c
)

find_package(Threads REQUIRED)

#target_compile_options(ping PRIVATE -fsanitize=address -g)
#target_link_options(ping PRIVATE -fsanitize=address)

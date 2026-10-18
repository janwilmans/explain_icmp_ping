cmake_minimum_required(VERSION 3.14 FATAL_ERROR)
project(ping VERSION 1.2)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.1.1
)
FetchContent_Declare(docopt
    GIT_REPOSITORY https://github.com/docopt/docopt.cpp.git
    GIT_TAG v0.6.3
)

FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(docopt)

add_compile_options(
    -Wall
    -Wextra
    -pedantic
    -Wcast-align
    -Wno-error=sign-conversion
    -Wno-error=conversion
    -Wformat=2
    -Wmisleading-indentation
    -Wmissing-include-dirs
    -Wnull-dereference
    -Wswitch-enum
    -Wunused
    -Wunused-variable
    -Wunused-parameter
    -Wvla
    -Werror=double-promotion
#   -Werror=sign-conversion
#   -Werror=conversion    
    -Werror
    # Warnings that are not allowed in C compilation units
    $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
    $<$<COMPILE_LANGUAGE:CXX>:-Woverloaded-virtual>
    $<$<COMPILE_LANGUAGE:CXX>:-Werror=suggest-override>
)

add_executable(ping
    network.cpp
    ping.cpp
)

target_link_libraries(ping
  PRIVATE
    fmt::fmt
    docopt
)

#target_compile_options(ping PRIVATE -fsanitize=address -g)
#target_link_options(ping PRIVATE -fsanitize=address)

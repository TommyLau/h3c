cmake_minimum_required(VERSION 3.10)
project(h3c C)

set(CMAKE_C_STANDARD 11)

# Git build version related
execute_process(
        COMMAND git rev-list HEAD --count
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BUILD
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_executable(h3c eapol.c h3c.c md5.c utils.c main.c)
target_compile_definitions(h3c PRIVATE -DBUILD_HASH="${GIT_BUILD}-${GIT_HASH}")

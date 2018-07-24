cmake_minimum_required(VERSION 3.9)
project(h3c C)

set(CMAKE_C_STANDARD 11)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_definitions(-DOS_DARWIN)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    add_definitions(-DOS_LINUX)
endif ()

# Git build version related
execute_process(
        COMMAND git describe --abbrev=0 --tags
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
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
target_compile_definitions(h3c PRIVATE -DBUILD_VERSION="${GIT_VERSION}" -DBUILD_HASH="b${GIT_BUILD}-${GIT_HASH}")

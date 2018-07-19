cmake_minimum_required(VERSION 3.10)
project(h3c C)

set(CMAKE_C_STANDARD 11)

add_executable(h3c eapol.c h3c.c md5.c utils.c main.c)
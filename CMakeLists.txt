cmake_minimum_required(VERSION 3.22)
project(elf_utils)

set(CMAKE_C_STANDARD 11)

include_directories(include)
add_library(elf_utils src/elf_utils.c src/ptrace.c)

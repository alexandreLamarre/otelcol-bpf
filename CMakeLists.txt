# This is a dumb project to help using IDE/tools to develop bpf program
# CLion can load cmake project
# Cmake+ninja can also generate compile_commands.json which may used by clangd etc
cmake_minimum_required(VERSION 3.26)
project(otelbpf C)
set(CMAKE_C_STANDARD 11)

add_library(otelbpf bpf/procexec/procexec.bpf.c)
target_include_directories(otelbpf PRIVATE include bpf/include/)
target_include_directories(otelbpf PRIVATE include /bpf/procexec/procexec.h)
target_compile_definitions(otelbpf PRIVATE -D__TARGET_ARCH_x86)
target_compile_options(otelbpf PRIVATE -nostdinc -nostdlib)
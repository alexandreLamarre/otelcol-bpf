# This is a dumb project to help using IDE/tools to develop bpf program
# CLion can load cmake project
# Cmake+ninja can also generate compile_commands.json which may used by clangd etc
cmake_minimum_required(VERSION 3.26)
project(otelbpf C)
set(CMAKE_C_STANDARD 11)

add_library(procexec bpf/procexec/procexec.bpf.c)
target_include_directories(procexec PRIVATE include bpf/include/)
target_include_directories(procexec PRIVATE include /bpf/procexec/procexec.h)
target_compile_definitions(procexec PRIVATE -D__TARGET_ARCH_x86)
target_compile_options(procexec PRIVATE -nostdinc -nostdlib)

add_library(tcptracer bpf/tcptracer/tcptracer.bpf.c)
target_include_directories(tcptracer PRIVATE include bpf/include/)
target_include_directories(tcptracer PRIVATE include /bpf/tcptracer/tcptracer.h)
target_include_directories(tcptracer PRIVATE include /bpf/tcptracer/tcptracer_maps.h)
target_compile_definitions(tcptracer PRIVATE -D__TARGET_ARCH_x86)
target_compile_options(tcptracer PRIVATE -nostdinc -nostdlib)

add_library(tcpconnlat bpf/tcpconnlat/tcpconnlat.bpf.c)
target_include_directories(tcpconnlat PRIVATE include bpf/include/)
target_include_directories(tcpconnlat PRIVATE include /bpf/tcpconnlat/tcpconnlat.h)
target_compile_definitions(tcpconnlat PRIVATE -D__TARGET_ARCH_x86)
target_compile_options(tcpconnlat PRIVATE -nostdinc -nostdlib)
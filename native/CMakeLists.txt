cmake_minimum_required(VERSION 3.22)
project(gpu_probe LANGUAGES CXX)

add_executable(gpu_probe probe.cpp)
set_target_properties(gpu_probe PROPERTIES
    OUTPUT_NAME "libgpu_probe"
    SUFFIX ".so"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES)
target_compile_options(gpu_probe PRIVATE -Wall -Wextra -Wpedantic -fPIE)
target_link_options(gpu_probe PRIVATE -pie)


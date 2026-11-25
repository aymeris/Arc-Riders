cmake_minimum_required(VERSION 3.15)
project(mapper_rt CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(mapper_rt mapper_rt.cpp)

if (MSVC)
    target_compile_options(mapper_rt PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(mapper_rt PRIVATE
        _UNICODE UNICODE
        WIN32_LEAN_AND_MEAN NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
endif()

target_link_libraries(mapper_rt PRIVATE advapi32)

cmake_minimum_required(VERSION 3.10...3.21)

project(socks_server VERSION "1.0.0" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose Release or Debug" FORCE)
endif()

set(CMAKE_CXX_FLAGS "-Wno-attributes")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -ggdb -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wno-unused -DNDEBUG")

set(BUILD_SHARED_LIBS ON)
add_subdirectory(third-party/spdlog-1.10.0)

message(STATUS "Build ${PROJECT_NAME}: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)

file(GLOB_RECURSE srcs ${PROJECT_BINARY_DIR}/../src/*.cpp)

include_directories(
    third-party/asio-1.24.0/include
    include
)

add_executable(${PROJECT_NAME} main.cpp ${srcs})

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(${PROJECT_NAME} PRIVATE
        pthread 
        spdlog::spdlog)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(${PROJECT_NAME} PRIVATE
        crypt32
        secur32
        ws2_32
        wsock32
        pthread
        spdlog::spdlog)
else()
    message(STATUS "This operating system is not supported")
endif()

cmake_minimum_required(VERSION 3.16)

project(SOCKS_SERVER)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

add_subdirectory(third-party/spdlog-1.10.0)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)

file(GLOB_RECURSE srcs ${PROJECT_BINARY_DIR}/../src/*.cpp)

add_library(socks5cpp SHARED
    ${srcs}
)

include_directories(
    third-party/asio-1.24.0/include
    include
)

add_executable(socks5 main.cpp)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(socks5 socks5cpp pthread spdlog::spdlog)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(socks5
        socks5cpp
        crypt32
        secur32
        ws2_32
        wsock32
        pthread
        spdlog::spdlog)
else()
    message(STATUS "Not Supported OS")
endif()

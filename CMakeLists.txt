cmake_minimum_required(VERSION 3.16)

project(SOCKS_SERVER)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)

include_directories(
    third-party/asio-1.24.0/include
    include
)

add_executable(socks5 main.cpp)

target_link_libraries(socks5 pthread)
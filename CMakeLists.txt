cmake_minimum_required(VERSION 3.10)

project(socks_server VERSION "4.5" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose Release or Debug" FORCE)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -ggdb -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

add_subdirectory(third-party/spdlog-1.9.0)

message(STATUS "Build ${PROJECT_NAME}: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if (NOT LOG_LEVEL)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG)
    else()
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
    endif()
else()
    if (LOG_LEVEL STREQUAL "Trace")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE)
    elseif(LOG_LEVEL STREQUAL "Debug")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG)
    elseif(LOG_LEVEL STREQUAL "Info")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
    elseif(LOG_LEVEL STREQUAL "Warn")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_WARN)
    elseif(LOG_LEVEL STREQUAL "Error")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_ERROR)
    elseif(LOG_LEVEL STREQUAL "Critical")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_CRITICAL)
    elseif(LOG_LEVEL STREQUAL "Off")
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_OFF)
    else()
        add_definitions(-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_DEBUG)
    endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/../bin)
set(SOCKS_LIB_NAME ${PROJECT_NAME}.${PROJECT_VERSION})

file(GLOB_RECURSE srcs ${PROJECT_BINARY_DIR}/../src/*.cpp)
file(GLOB_RECURSE hdrs ${PROJECT_BINARY_DIR}/../include/*.h)

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/third-party/asio-1.24.0/include
    ${PROJECT_SOURCE_DIR}/third-party/nlohmann-3.11.2/single_include
)

add_executable(${PROJECT_NAME} main.cpp)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(${SOCKS_LIB_NAME} STATIC ${srcs})

    target_link_libraries(${SOCKS_LIB_NAME} PUBLIC
        pthread
        spdlog::spdlog)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(${SOCKS_LIB_NAME} STATIC ${srcs})

    target_link_libraries(${SOCKS_LIB_NAME} PUBLIC
        ws2_32
        wsock32
        spdlog::spdlog)
else()
    message(STATUS "This operating system is not supported")
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC ${SOCKS_LIB_NAME})


# ---------------------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------------------
include(GNUInstallDirs)

set(INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/${PROJECT_NAME}/${CMAKE_BUILD_TYPE}/${CMAKE_INSTALL_BINDIR})
set(INSTALL_SYSCONF ${CMAKE_INSTALL_PREFIX}/${PROJECT_NAME}/${CMAKE_BUILD_TYPE})

install(TARGETS ${PROJECT_NAME} ${SOCKS_LIB_NAME}
    ARCHIVE
        DESTINATION ${INSTALL_BINDIR}
    LIBRARY
        DESTINATION ${INSTALL_BINDIR}
    RUNTIME
        DESTINATION ${INSTALL_BINDIR}
)

install(
    FILES ${CMAKE_SOURCE_DIR}/config.json
        DESTINATION ${INSTALL_SYSCONF}
)

# ---------------------------------------------------------------------------------------
# Valgrind
# ---------------------------------------------------------------------------------------
find_program(VALGRIND_EXECUTABLE
    NAMES "valgrind"
    PATHS "/usr/bin" "/usr/local/bin"
)

if (VALGRIND_EXECUTABLE)
    message(STATUS "Successfully find program `valgrind`")
    message(STATUS "You can use the `make valgrind` command to perform memory leak detection")
    add_custom_target(valgrind
    COMMAND
        ${VALGRIND_EXECUTABLE} --log-file=memcheck.log --leak-check=full $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT
        "Perform memory leak detection, end with `Ctrl + C`"
    )
endif()

# ---------------------------------------------------------------------------------------
# Clang-Format
# ---------------------------------------------------------------------------------------
find_program(CLANG_FORMAT_EXECUTABLE
    NAME "clang-format-12"
    PATHS "/usr/bin" "/usr/local/bin"
)

if (CLANG_FORMAT_EXECUTABLE)
    message(STATUS "Successfully find program `clang-format-12`")
    message(STATUS "You can use the `make clang-format` command to automatically format the code style")
    add_custom_target(clang-format
    COMMAND
        ${CLANG_FORMAT_EXECUTABLE} --style=file -i ${hdrs};${srcs};${PROJECT_BINARY_DIR}/../main.cpp
    COMMENT
        "Automatically format the code style"
    )
endif()
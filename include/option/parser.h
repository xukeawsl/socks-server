#pragma once

#include "common/common.h"

class ServerParser {
public:
    explicit ServerParser(const std::string& config_file);
    ~ServerParser() = default;

    inline std::string get_host() const { return host; }

    inline uint16_t get_port() const { return port; }

    inline size_t get_thread_num() const { return thread_num; }

    inline std::string get_log_file() const { return log_file; }

    inline long unsigned get_max_rotate_size() const { return max_rotate_size; }

    inline long unsigned get_max_rotate_count() const {
        return max_rotate_count;
    }

private:
    std::string host;
    uint16_t port;
    size_t thread_num;
    std::string log_file;
    long unsigned max_rotate_size;
    long unsigned max_rotate_count;
};
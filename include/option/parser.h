#pragma once

#include "common/common.h"
#include "common/socks5_type.h"

class ServerParser {
public:
    static ServerParser* global_config() {
        static ServerParser parser;
        return &parser;
    }

    bool parse_config_file(const std::string& config_file);

    inline std::string get_host() const { return host; }

    inline uint16_t get_port() const { return port; }

    inline size_t get_thread_num() const { return thread_num; }

    inline std::string get_log_file() const { return log_file; }

    inline long unsigned get_max_rotate_size() const { return max_rotate_size; }

    inline long unsigned get_max_rotate_count() const {
        return max_rotate_count;
    }

    inline size_t get_conn_timeout() const { return conn_timeout; }

    inline bool is_supported_method(SocksV5::Method method) const {
        return supported_methods.count(method) > 0;
    }

    inline bool check_username(const std::string& uname) const {
        return username == uname;
    }

    inline bool check_password(const std::string& passwd) const {
        return password == passwd;
    }

private:
    explicit ServerParser();
    ~ServerParser() = default;

private:
    std::string host;
    uint16_t port;
    size_t thread_num;
    size_t conn_timeout;
    std::string log_file;
    long unsigned max_rotate_size;
    long unsigned max_rotate_count;
    std::string username;
    std::string password;
    std::unordered_set<SocksV5::Method> supported_methods;
};
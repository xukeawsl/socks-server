#include "option/parser.h"

#include "nlohmann/json.hpp"

using json = nlohmann::json;

ServerParser::ServerParser()
    : host("127.0.0.1"),
      port(1080),
      thread_num(std::thread::hardware_concurrency()),
      conn_timeout(10 * 60),
      log_file("logs/server.log"),
      max_rotate_size(1024 * 1024),
      max_rotate_count(10) {}

bool ServerParser::parse_config_file(const std::string& config_file) {
    std::ifstream f(config_file);
    json data = json::parse(f);
    auto server_config = data["server"];
    if (server_config.is_object() && !server_config.empty()) {
        if (server_config.contains("host")) {
            host = server_config["host"].get<std::string>();
        }
        if (server_config.contains("port")) {
            port = server_config["port"].get<uint16_t>();
        }
        if (server_config.contains("thread_num")) {
            thread_num = server_config["thread_num"].get<size_t>();
        }
    }
    auto log_config = data["log"];
    if (log_config.is_object() && !log_config.empty()) {
        if (log_config.contains("log_file")) {
            log_file = log_config["log_file"].get<std::string>();
        }
        if (log_config.contains("max_rotate_size")) {
            max_rotate_size =
                log_config["max_rotate_size"].get<long unsigned>();
        }
        if (log_config.contains("max_rotate_count")) {
            max_rotate_count =
                log_config["max_rotate_count"].get<long unsigned>();
        }
    }
    auto auth_config = data["auth"];
    if (auth_config.is_object() && !auth_config.empty()) {
        if (auth_config.contains("username")) {
            username = auth_config["username"].get<std::string>();
        } else {
            return false;
        }
        if (auth_config.contains("password")) {
            password = auth_config["password"].get<std::string>();
        } else {
            return false;
        }
    }
    auto methods_config = data["supported-methods"];
    if (methods_config.is_array() && !methods_config.empty()) {
        for (size_t i = 0; i < methods_config.size(); i++) {
            supported_methods.emplace(methods_config[i].get<SocksV5::Method>());
        }
    } else {    // 支持方法必填
        return false;
    }

    auto timeout_config = data["timeout"];
    if (timeout_config.is_number_unsigned()) {
        conn_timeout = timeout_config.get<size_t>();
    }

    return true;
}
#include "option/parser.h"
#include "socks5/socks5_server.h"

void signal_handler(const asio::error_code& ec, int signal) {
    if (signal != SIGINT) {
        SPDLOG_ERROR("Socks Server Abnormal Exit!");
    }
}

int main(int argc, char* argv[]) {
    // parse command options
    if (ServerParser::global_config()->parse_config_file("../config.json") !=
        true) {
        std::cout << "bad configuration file !!!" << std::endl;
        return EXIT_FAILURE;
    }
    // execute socks server loop
    asio::io_context waiter;
    asio::signal_set sig(waiter, SIGINT);
    sig.async_wait(signal_handler);
    // init log config
    if (Logger::getInstance()->Init(
            ServerParser::global_config()->get_log_file(),
            ServerParser::global_config()->get_max_rotate_size(),
            ServerParser::global_config()->get_max_rotate_count())) {
        SPDLOG_INFO("Log initialization succeeded");
        SPDLOG_INFO("log_file : {}",
                    ServerParser::global_config()->get_log_file());
        SPDLOG_INFO("max_rotate_size : {} Bytes",
                    ServerParser::global_config()->get_max_rotate_size());
        SPDLOG_INFO("max_rotate_count : {}",
                    ServerParser::global_config()->get_max_rotate_count());
    } else {
        SPDLOG_INFO("Log initialization failed!");
        return EXIT_FAILURE;
    }
    Socks5Server server(ServerParser::global_config()->get_host(),
                        ServerParser::global_config()->get_port(),
                        ServerParser::global_config()->get_thread_num());
    server.start();

    waiter.run();
    return EXIT_SUCCESS;
}
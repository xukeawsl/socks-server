#include "option/parser.h"
#include "socks5/socks5_server.h"

void signal_handler(const asio::error_code& ec, int signal) {
    if (signal != SIGINT) {
        SPDLOG_ERROR("Socks Server Abnormal Exit!");
    }
}

int main(int argc, char* argv[]) {
    // parse command options
    ServerParser parser("../config.json");
    // execute socks server loop
    asio::io_context waiter;
    asio::signal_set sig(waiter, SIGINT);
    sig.async_wait(signal_handler);
    // init log config
    if (Logger::getInstance()->Init(parser.get_log_file(),
                                    parser.get_max_rotate_size(),
                                    parser.get_max_rotate_count())) {
        SPDLOG_INFO("Log initialization succeeded");
        SPDLOG_DEBUG("log_file : {}", parser.get_log_file());
        SPDLOG_DEBUG("max_rotate_size : {} Bytes",
                     parser.get_max_rotate_size());
        SPDLOG_DEBUG("max_rotate_count : {}", parser.get_max_rotate_count());
    } else {
        SPDLOG_INFO("Log initialization failed!");
        return EXIT_FAILURE;
    }
    Socks5Server server(parser.get_host(), parser.get_port(),
                        parser.get_thread_num());
    server.start();

    waiter.run();
    return EXIT_SUCCESS;
}
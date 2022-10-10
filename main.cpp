#include "socks5/socks5_server.h"

void signal_handler(const asio::error_code& ec, int signal) {
    if (signal == SIGINT) {
        spdlog::info("Socks Server Normal Exit");
    } else {
        spdlog::error("Socks Server Abnormal Exit!");
    }
}

int main(int argc, char* argv[]) {
    asio::io_context waiter;
    asio::signal_set sig(waiter, SIGINT);
    sig.async_wait(signal_handler);

    Logger::getInstance()->Init();
    spdlog::info("hello {}", "world");
    Socks5Server server("0.0.0.0", 7777);
    server.start();

    waiter.run();
    return 0;
}
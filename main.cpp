#include "option/parser.h"
#include "socks5/socks5_server.h"

void signal_handler(const asio::error_code& ec, int signal) {
    if (signal != SIGINT) {
        SPDLOG_ERROR("Socks Server Abnormal Exit!");
    }
}

int main(int argc, char* argv[]) {
    // parse command options

    // execute socks server loop
    asio::io_context waiter;
    asio::signal_set sig(waiter, SIGINT);
    sig.async_wait(signal_handler);

    Logger::getInstance()->Init();
    Socks5Server server("0.0.0.0", 7777);
    server.start();

    waiter.run();
    return 0;
}
#pragma once

#include "common.h"
#include "socks5_connect.h"

class Socks5Server : public noncopyable {
public:
    explicit Socks5Server(const std::string& host = "127.0.0.1",
                          uint16_t port = 1080);

    ~Socks5Server();

    void loop();

    void start();

    void stop();

private:
    void wait_for_client();

protected:
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor;
    std::vector<std::thread> work_threads;
};
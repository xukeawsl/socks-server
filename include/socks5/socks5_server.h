#pragma once

#include "common/common.h"
#include "socks5_connect.h"
#include "util/io_context_pool.h"

class Socks5Server : public noncopyable {
public:
    explicit Socks5Server(const std::string& host, uint16_t port,
                          size_t thread_num);

    ~Socks5Server();

    void start();

private:
    void wait_for_client();

    void stop();

protected:
    size_t pool_size;
    size_t conn_timeout;
    io_context_pool pool;
    asio::signal_set signals;
    asio::ip::tcp::acceptor acceptor;
    std::shared_ptr<Socks5Connection> new_conn_ptr;
};
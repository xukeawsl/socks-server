#pragma once

#include "common/common.h"
#include "socks5_connect.h"

class Socks5Server : public noncopyable {
private:
    using io_context_ptr = std::shared_ptr<asio::io_context>;
    using block_work_ptr = std::shared_ptr<asio::io_context::work>;

public:
    explicit Socks5Server(const std::string& host, uint16_t port,
                          size_t thread_num);

    ~Socks5Server();

    void start();

    void stop();

private:
    void wait_for_client();

    inline asio::io_context& get_io_context();

protected:
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor;
    size_t pool_size;
    size_t next_idx;
    std::vector<io_context_ptr> io_context_pool;
    std::vector<std::thread> work_threads;
    std::vector<block_work_ptr> block_works;
};
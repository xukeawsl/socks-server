#include "socks5/socks5_server.h"

Socks5Server::Socks5Server(const std::string& host, uint16_t port,
                           size_t thread_num)
    : acceptor(ioc,
               asio::ip::tcp::endpoint(asio::ip::make_address(host), port)),
      pool_size(thread_num),
      next_idx(0) {
    for (size_t i = 0; i < pool_size; i++) {
        io_context_ptr ioc_ptr = std::make_shared<asio::io_context>();
        io_context_pool.emplace_back(ioc_ptr);
        block_works.emplace_back(
            std::make_shared<asio::io_context::work>(*ioc_ptr));
    }
}

Socks5Server::~Socks5Server() {
    stop();
    spdlog::shutdown();
}

void Socks5Server::start() {
    try {
        // session thread
        for (size_t i = 0; i < pool_size; i++) {
            work_threads.emplace_back(
                [this](size_t ioc_idx) {
                    this->io_context_pool[ioc_idx]->run();
                },
                i);
        }
        // accept thread
        work_threads.emplace_back([this] {
            this->wait_for_client();
            this->ioc.run();
        });
    } catch (asio::system_error& e) {
        SPDLOG_ERROR("Socks Server Exception: {}", e.what());
    }
    SPDLOG_INFO("Socks Server Start");
    SPDLOG_INFO("Socks Server Listen on {}:{}",
                acceptor.local_endpoint().address().to_string(),
                acceptor.local_endpoint().port());
    SPDLOG_INFO("Socks Server Work Thread Num : {}", pool_size);
}

void Socks5Server::stop() {
    block_works.clear();
    ioc.stop();
    for (auto& ioc_ptr : io_context_pool) {
        ioc_ptr->stop();
    }
    for (auto& work_thread : work_threads) {
        if (work_thread.joinable()) {
            work_thread.join();
        }
    }
    SPDLOG_INFO("Socks Server Stop");
}

void Socks5Server::wait_for_client() {
    acceptor.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            // 不论 accept 成功还是失败都要继续监听
            wait_for_client();
            if (!ec) {
                socket.set_option(asio::ip::tcp::no_delay(true));
                // 用智能指针延续 socket 的生命期
                auto conn_ptr = std::make_shared<Socks5Connection>(
                    get_io_context(), std::move(socket));
                conn_ptr->start();
            } else {
                SPDLOG_DEBUG("Connection Denied : {}", ec.message());
            }
        });
}

asio::io_context& Socks5Server::get_io_context() {
    asio::io_context& ioc_ref = *io_context_pool[next_idx++];
    if (next_idx == pool_size) next_idx = 0;
    return ioc_ref;
}
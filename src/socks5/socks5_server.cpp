#include "socks5/socks5_server.h"

Socks5Server::Socks5Server(const std::string& host, uint16_t port,
                           size_t thread_num)
    : acceptor(ioc,
               asio::ip::tcp::endpoint(asio::ip::make_address(host), port)),
      work_threads(thread_num) {}

Socks5Server::~Socks5Server() { stop(); }

void Socks5Server::loop() {
    start();
    ioc.run();
}

void Socks5Server::start() {
    try {
        for (auto& work_thread : work_threads) {
            work_thread = std::thread([this] {
                this->wait_for_client();
                ioc.run();
            });
        }
    } catch (std::exception& e) {
        SPDLOG_ERROR("Socks Server Exception: {}", e.what());
    }
    SPDLOG_INFO("Socks Server Start");
    SPDLOG_DEBUG("Socks Server Listen on {}:{}",
                 acceptor.local_endpoint().address().to_string(),
                 acceptor.local_endpoint().port());
    SPDLOG_DEBUG("Socks Server Work Thread Num : {}", work_threads.size());
}

void Socks5Server::stop() {
    ioc.stop();
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
                // 用智能指针延续 socket 的生命期
                auto conn_ptr =
                    std::make_shared<Socks5Connection>(ioc, std::move(socket));
                conn_ptr->start();
            } else {
                SPDLOG_DEBUG("Connection Denied : {}", ec.message());
            }
        });
}
#include "socks5/socks5_server.h"

Socks5Server::Socks5Server(const std::string& host, uint16_t port)
        : acceptor(ioc, asio::ip::tcp::endpoint(asio::ip::make_address(host), port)),
          work_threads(std::thread::hardware_concurrency()) {}

Socks5Server::~Socks5Server() {
    stop();
}

void Socks5Server::loop() {
    start();
    ioc.run();
}

void Socks5Server::start() {
    try {
        wait_for_client();
        for (auto& work_thread : work_threads) {
            work_thread = std::thread([this]{ ioc.run(); });
        }
    } catch (std::exception& e) {
        std::cerr << "[Socks5] Exception: " << e.what() << '\n';
    }
    std::cout << "[Socks5] Started!\n";
}

void Socks5Server::stop() {
    ioc.stop();
    for (auto& work_thread : work_threads) {
        if (work_thread.joinable()) {
            work_thread.join();
        }
    }
    std::cout << "[Socks5] Stoped!\n";
}

void Socks5Server::wait_for_client() {
    acceptor.async_accept([this](std::error_code ec, asio::ip::tcp::socket socket) {
        // 不论 accept 成功还是失败都要继续监听
        wait_for_client();
        if (!ec) {
            std::cout << "[Socks5] New Connection: " << socket.remote_endpoint() << '\n';
            std::cout << "thread id : " << std::this_thread::get_id() << '\n';
            
            // 用智能指针延续 socket 的生命期
            auto conn_ptr = std::make_shared<Socks5Connection>(ioc, std::move(socket));
            conn_ptr->start();
        } else {
            std::cout << "Connection Denied\n";
        }
    });
}
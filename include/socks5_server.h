#pragma once

#include "common.h"
#include "socks5_connect.h"

class Socks5Server : public noncopyable {
public:
    explicit Socks5Server(const std::string& host = "127.0.0.1", uint16_t port = 1080)
        : acceptor(ioc, asio::ip::tcp::endpoint(asio::ip::make_address(host), port)),
          work_threads(std::thread::hardware_concurrency())
          {}

    ~Socks5Server() {
        stop();
    }

    void loop() {
        start();
        ioc.run();
    }

    void start() {
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

    void stop() {
        ioc.stop();
        for (auto& work_thread : work_threads) {
            if (work_thread.joinable()) {
                work_thread.join();
            }
        }
        std::cout << "[Socks5] Stoped!\n";
    }

private:
    void wait_for_client() {
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

protected:
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor;
    std::vector<std::thread> work_threads;
};
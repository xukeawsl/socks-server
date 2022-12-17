#include "socks5/socks5_server.h"

Socks5Server::Socks5Server(const std::string& host, uint16_t port,
                           size_t thread_num)
    : pool_size(thread_num),
      conn_timeout(ServerParser::global_config()->get_conn_timeout()),
      pool(pool_size),
      signals(pool.get_io_context()),
      acceptor(pool.get_io_context()),
      new_conn_ptr() {
    signals.add(SIGINT);
    signals.add(SIGTERM);
#if defined(SIGQUIT)
    signals.add(SIGQUIT);
#endif
    signals.async_wait(std::bind(&Socks5Server::stop, this));

    asio::ip::tcp::resolver resolver(acceptor.get_executor());
    asio::ip::tcp::endpoint endpoint =
        *resolver.resolve(host, std::to_string(port)).begin();
    acceptor.open(endpoint.protocol());
    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();

    wait_for_client();
}

Socks5Server::~Socks5Server() {
    stop();
    spdlog::shutdown();
}

void Socks5Server::start() {
    SPDLOG_INFO("Socks Server Start");
    SPDLOG_INFO("Socks Server Listen on {}:{}",
                acceptor.local_endpoint().address().to_string(),
                acceptor.local_endpoint().port());
    SPDLOG_INFO("Socks Server Work Thread Num : {}", pool_size);
    SPDLOG_INFO("Socks Server Connection Timeout : {}s", conn_timeout);
    try {
        pool.run();
    } catch (std::system_error& e) {
        SPDLOG_ERROR("Socks Server Error: {}", e.what());
    }
}

void Socks5Server::stop() {
    pool.stop();

    SPDLOG_INFO("Socks Server Stop");
}

void Socks5Server::wait_for_client() {
    new_conn_ptr.reset(new Socks5Connection(pool.get_io_context()));
    acceptor.async_accept(
        new_conn_ptr->get_socket(), [this](std::error_code ec) {
            if (!ec) {
                this->new_conn_ptr->set_timeout(this->conn_timeout);
                this->new_conn_ptr->start();
            } else {
                SPDLOG_DEBUG("Connection Denied : {}", ec.message());
            }
            // 不论 accept 成功还是失败都要继续监听
            wait_for_client();
        });
}
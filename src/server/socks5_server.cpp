#include "server/socks5_server.h"
#include "session/socks5_session.h"

Socks5Server::Socks5Server(const std::string& host, uint16_t port,
                           size_t thread_num)
    : pool_size(thread_num),
      conn_timeout(ServerParser::global_config()->get_conn_timeout()),
      pool(pool_size),
      signals(pool.get_io_context()),
      acceptor(pool.get_io_context()),
      listen_endpoint(asio::ip::make_address(host), port),
      new_conn_ptr() {}

void Socks5Server::start() noexcept {
    try {
        init();

        SPDLOG_INFO("Socks5 Server Start");
        SPDLOG_INFO("Socks5 Server Listening on {}",
                    convert::format_address(listen_endpoint));
        SPDLOG_INFO("Socks5 Server Listening Address Type : {}",
                    listen_endpoint.address().is_v4() ? "IPv4" : "IPv6");
        SPDLOG_INFO("Socks5 Server Work Thread Num : {}", pool_size);
        SPDLOG_INFO("Socks5 Server Connection Timeout : {}s", conn_timeout);

        do_accept();

        pool.run();
    } catch (const std::exception& e) {
        SPDLOG_ERROR("Socks5 Server Failed to Start : ERR_MSG = [{}])",
                     std::string(e.what()));
    }
}

void Socks5Server::stop() {
    SPDLOG_INFO("Socks Server Stop");
    pool.stop();
    spdlog::shutdown();
}

void Socks5Server::init() {
    signals.add(SIGINT);
    signals.add(SIGTERM);
#if defined(SIGQUIT)
    signals.add(SIGQUIT);
#endif
    signals.async_wait(std::bind(&Socks5Server::stop, this));

    acceptor.open(listen_endpoint.protocol());
    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(listen_endpoint);
    acceptor.listen();
}

void Socks5Server::do_accept() {
    new_conn_ptr.reset(new Socks5Session(pool.get_io_context()));
    acceptor.async_accept(
        new_conn_ptr->get_socket(), [this](std::error_code ec) {
            if (!ec) {
                this->new_conn_ptr->set_timeout(this->conn_timeout);
                this->new_conn_ptr->start();
            } else {
                SPDLOG_DEBUG("Failed to Accept Connection : {}", ec.message());
            }

            do_accept();
        });
}
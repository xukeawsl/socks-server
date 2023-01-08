#include "socks5/socks5_connect.h"

Socks5Connection::Socks5Connection(asio::io_context& ioc_)
    : ioc(ioc_), socket(ioc_), dst_socket(ioc_), deadline(ioc_) {
    deadline.expires_at(asio::steady_timer::time_point::max());
}

asio::ip::tcp::socket& Socks5Connection::get_socket() { return this->socket; }

void Socks5Connection::start() {
    if (socket.is_open()) {
        try {
            uint8_t addr[4] = {0};
            std::sscanf(socket.remote_endpoint().address().to_string().c_str(),
                        "%hhu.%hhu.%hhu.%hhu", &addr[0], &addr[1], &addr[2],
                        &addr[3]);
            cli_addr = {addr[0], addr[1], addr[2], addr[3]};
            cli_port = socket.remote_endpoint().port();

            local_host = socket.local_endpoint().address().to_string();
            local_port = socket.local_endpoint().port();

            SPDLOG_DEBUG("New Connection {}.{}.{}.{}:{}",
                         static_cast<int16_t>(this->cli_addr[0]),
                         static_cast<int16_t>(this->cli_addr[1]),
                         static_cast<int16_t>(this->cli_addr[2]),
                         static_cast<int16_t>(this->cli_addr[3]),
                         this->cli_port);

            this->check_deadline();
            this->keep_alive();
            this->get_version_and_nmethods();
        } catch (const asio::system_error&) {
            SPDLOG_DEBUG("Client Disconnected");
            this->stop();
        }
    }
}

void Socks5Connection::set_timeout(size_t second) { this->timeout = second; }

void Socks5Connection::keep_alive() {
    if (timeout > 0) {
        SPDLOG_TRACE("Connection Keep Alive");
        deadline.expires_after(asio::chrono::seconds(timeout));
    }
}

void Socks5Connection::check_deadline() {
    if (!socket.is_open() && !dst_socket.is_open()) {
        return;
    }

    if (deadline.expiry() <= asio::steady_timer::clock_type::now()) {
        SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Timeout",
                     static_cast<int16_t>(this->cli_addr[0]),
                     static_cast<int16_t>(this->cli_addr[1]),
                     static_cast<int16_t>(this->cli_addr[2]),
                     static_cast<int16_t>(this->cli_addr[3]), this->cli_port);
        this->stop();
    } else {
        auto self = shared_from_this();
        deadline.async_wait(std::bind(&Socks5Connection::check_deadline, self));
    }
}

void Socks5Connection::stop() {
    asio::error_code ignored_ec;
    socket.close(ignored_ec);
    dst_socket.close(ignored_ec);
    deadline.cancel(ignored_ec);
}

void Socks5Connection::get_version_and_nmethods() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&nmethods, 1)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "NMETHODS = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->nmethods));

                if (this->ver != SocksVersion::V5) {
                    SPDLOG_DEBUG("Unsupported protocol version");
                    this->stop();
                }

                this->methods.resize(this->nmethods);
                this->get_methods_list();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_methods_list() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->methods.data(), this->methods.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [METHODS "
                    "={:Xpn}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    spdlog::to_hex(this->methods.begin(), this->methods.end()));

                this->keep_alive();
                this->method = this->choose_method();
                this->reply_support_method();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

SocksV5::Method Socks5Connection::choose_method() {
    for (auto method : this->methods) {
        if (ServerParser::global_config()->is_supported_method(method)) {
            return method;
        }
    }
    return SocksV5::Method::NoAcceptable;
}

void Socks5Connection::reply_support_method() {
    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&method, 1)}};

    auto self = shared_from_this();
    asio::async_write(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "METHOD = X'{:02x}']",
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->method));

                this->keep_alive();
                switch (this->method) {
                    case SocksV5::Method::NoAuth:
                        this->get_socks_request();
                        break;

                    case SocksV5::Method::UserPassWd:
                        this->get_username_length();
                        break;

                    case SocksV5::Method::GSSAPI:
                        // not supported
                        break;

                    case SocksV5::Method::NoAcceptable:
                        this->stop();
                        break;
                }

            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_username_length() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&ulen, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', ULEN "
                    "= {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->ulen));

                this->uname.resize(static_cast<std::size_t>(this->ulen));
                this->get_username_content();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_username_content() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->uname.data(), this->uname.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [UNAME = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    std::string(this->uname.begin(), this->uname.end()));

                this->get_password_length();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_password_length() {
    std::array<asio::mutable_buffer, 1> buf = {{asio::buffer(&plen, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [PLEN = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->plen));

                this->passwd.resize(static_cast<std::size_t>(this->plen));
                this->get_password_content();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_password_content() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->passwd.data(), this->passwd.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [PASSWD = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    std::string(this->passwd.begin(), this->passwd.end()));

                this->keep_alive();
                this->auth_and_respond();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::auth_and_respond() {
    if (ServerParser::global_config()->check_username(
            std::string(uname.begin(), uname.end())) &&
        ServerParser::global_config()->check_password(
            std::string(passwd.begin(), passwd.end()))) {
        status = SocksV5::ReplyAuthStatus::Success;
    } else {
        status = SocksV5::ReplyAuthStatus::Failure;
    }

    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&status, 1)}};

    auto self = shared_from_this();
    asio::async_write(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "STATUS = X'{:02x}']",
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->status));

                if (this->status == SocksV5::ReplyAuthStatus::Success) {
                    this->get_socks_request();
                } else {
                    this->stop();
                }
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_socks_request() {
    std::array<asio::mutable_buffer, 4> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&cmd, 1), asio::buffer(&rsv, 1),
         asio::buffer(&request_atyp, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', CMD "
                    "= X'{:02x}, RSV = X'{:02x}', ATYP = X'{:02x}']",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->cmd),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->request_atyp));

                this->keep_alive();
                this->get_dst_information();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::get_dst_information() {
    reply_atyp = SocksV5::ReplyATYP::Ipv4;    // reply only supported ipv4

    if (request_atyp == SocksV5::RequestATYP::Ipv4) {
        dst_addr.resize(4);
        parse_ipv4();
    } else if (request_atyp == SocksV5::RequestATYP::DoMainName) {
        dst_addr.resize(UINT8_MAX);
        parse_domain();
    } else if (request_atyp == SocksV5::RequestATYP::Ipv6) {
        dst_addr.resize(16);
        parse_ipv6();
    }
}

void Socks5Connection::parse_ipv4() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(dst_addr.data(), dst_addr.size()),
         asio::buffer(&dst_port, 2)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // network octet order convert to host octet order
                this->dst_port = ntohs(this->dst_port);

                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [DST.ADDR = "
                    "{}.{}.{}.{}, DST.PORT = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port);

                this->keep_alive();
                this->execute_command();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::parse_ipv6() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(dst_addr.data(), dst_addr.size()),
         asio::buffer(&dst_port, 2)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // network octet order convert to host octet order
                this->dst_port = ntohs(this->dst_port);
                std::string ipv6_host = To16(this->dst_addr);

                asio::ip::tcp::resolver resolver(this->ioc);

                this->keep_alive();
                try {
                    auto endpoints = resolver.resolve(
                        ipv6_host, std::to_string(this->dst_port));

                    std::string host =
                        endpoints->endpoint().address().to_string();
                    uint8_t addr[4] = {0};
                    std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0],
                                &addr[1], &addr[2], &addr[3]);

                    SPDLOG_DEBUG(
                        "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [DST.ADDR "
                        "= "
                        "{}, DST.PORT = {}]",
                        static_cast<int16_t>(this->cli_addr[0]),
                        static_cast<int16_t>(this->cli_addr[1]),
                        static_cast<int16_t>(this->cli_addr[2]),
                        static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                        this->local_host, this->local_port, ipv6_host,
                        this->dst_port);
                    this->dst_addr = {addr[0], addr[1], addr[2], addr[3]};
                    this->execute_command();
                } catch (const asio::system_error&) {
                    SPDLOG_WARN("IPv6: {} Resolve Failed", ipv6_host);
                    this->rep = SocksV5::ReplyREP::HostUnreachable;
                    this->bnd_addr = {0, 0, 0, 0};
                    this->bnd_port = 0;
                    this->reply_connect_result();
                }
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::parse_domain() { parse_domain_length(); }

void Socks5Connection::parse_domain_length() {
    std::array<asio::mutable_buffer, 1> buf = {
        asio::buffer(dst_addr.data(), 1)};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : "
                    "[DOMAIN_LENGTH = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->dst_addr[0]));
                this->parse_domain_content(this->dst_addr[0]);
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::parse_domain_content(size_t read_length) {
    std::array<asio::mutable_buffer, 1> buf = {
        asio::buffer(dst_addr.data(), read_length)};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                this->dst_addr.resize(length);
                this->parse_port();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::parse_port() {
    std::array<asio::mutable_buffer, 1> buf = {asio::buffer(&dst_port, 2)};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // 网络字节序转主机字节序
                this->dst_port = ntohs(this->dst_port);

                std::string domain;
                for (auto ch : dst_addr) {
                    domain.push_back(static_cast<char>(ch));
                }

                this->keep_alive();
                asio::ip::tcp::resolver resolver(this->ioc);
                try {
                    auto endpoints = resolver.resolve(
                        domain, std::to_string(this->dst_port));

                    std::string host =
                        endpoints->endpoint().address().to_string();
                    uint8_t addr[4];
                    memset(addr, 0, sizeof(addr));
                    std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0],
                                &addr[1], &addr[2], &addr[3]);

                    SPDLOG_DEBUG(
                        "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : "
                        "[DOMAIN_CONTENT = "
                        "{}({}.{}.{}.{}:{})]",
                        static_cast<int16_t>(this->cli_addr[0]),
                        static_cast<int16_t>(this->cli_addr[1]),
                        static_cast<int16_t>(this->cli_addr[2]),
                        static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                        this->local_host, this->local_port, domain,
                        static_cast<int16_t>(addr[0]),
                        static_cast<int16_t>(addr[1]),
                        static_cast<int16_t>(addr[2]),
                        static_cast<int16_t>(addr[3]), this->dst_port);

                    this->dst_addr = {addr[0], addr[1], addr[2], addr[3]};
                    this->execute_command();
                } catch (const asio::system_error&) {
                    SPDLOG_WARN("DOMAIN_CONTENT: {} Resolve Failed", domain);
                    this->rep = SocksV5::ReplyREP::HostUnreachable;
                    this->bnd_addr = {0, 0, 0, 0};
                    this->bnd_port = 0;
                    this->reply_connect_result();
                }
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::execute_command() {
    switch (cmd) {
        case SocksV5::RequestCMD::Connect:
            connect_dst_host();
            break;
        case SocksV5::RequestCMD::Bind:
            /*not supported*/
            this->stop();
            break;
        case SocksV5::RequestCMD::UdpAssociate:
            reply_udp_associate();
            break;
        default:
            this->stop();
            break;
    }
}

void Socks5Connection::connect_dst_host() {
    auto self = shared_from_this();
    std::string host = To4(dst_addr);

    dst_socket.async_connect(
        asio::ip::tcp::endpoint(asio::ip::address::from_string(host), dst_port),
        [this, self](asio::error_code ec) {
            if (!ec) {
                this->rep = SocksV5::ReplyREP::Succeeded;

                std::string host;
                try {
                    this->bnd_port = this->dst_socket.local_endpoint().port();
                    host =
                        this->dst_socket.local_endpoint().address().to_string();
                } catch (const asio::system_error&) {
                    this->stop();
                }

                uint8_t addr[4] = {0};
                std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0],
                            &addr[1], &addr[2], &addr[3]);
                this->bnd_addr = {addr[0], addr[1], addr[2], addr[3]};

                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Server {}.{}.{}.{}:{} Connection Successed",
                    host, this->bnd_port,
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port);

                this->keep_alive();
                this->reply_connect_result();
            } else {
                SPDLOG_DEBUG("Server {}.{}.{}.{}:{} Connection Failed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
                this->stop();
            }
        });
}

void Socks5Connection::reply_udp_associate() {
    try {
        udp_socket.reset(new asio::ip::udp::socket(
            ioc, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)));

        uint8_t addr[4] = {0};
        std::sscanf(udp_socket->local_endpoint().address().to_string().c_str(),
                    "%hhu.%hhu.%hhu.%hhu", &addr[0], &addr[1], &addr[2],
                    &addr[3]);
        bnd_addr = {addr[0], addr[1], addr[2], addr[3]};
        // host octet order convert to network octet order
        bnd_port = htons(udp_socket->local_endpoint().port());

        SPDLOG_DEBUG("Udp Associate Socket Listen on: {}.{}.{}.{}:{}",
                     bnd_addr[0], bnd_addr[1], bnd_addr[2], bnd_addr[3],
                     ntohs(bnd_port));
    } catch (const asio::system_error&) {
        SPDLOG_WARN("Udp Associate Failed");
    }

    rep = SocksV5::ReplyREP::Succeeded;
    reply_atyp = SocksV5::ReplyATYP::Ipv4;

    std::array<asio::mutable_buffer, 6> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&rep, 1), asio::buffer(&rsv, 1),
         asio::buffer(&reply_atyp, 1), asio::buffer(bnd_addr.data(), 4),
         asio::buffer(&bnd_port, 2)}};

    auto self = shared_from_this();
    asio::async_write(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // recovery from networks octet order after send to client
                this->bnd_port = ntohs(this->bnd_port);

                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', REP "
                    "= X'{:02x}', RSV = X'{:02x}' "
                    "ATYP = X'{:02x}', BND.ADDR = {}.{}.{}.{}, BND.PORT = {}]",
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->rep),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->reply_atyp),
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port);
                // prepare buffer
                this->client_buffer.resize(BUFSIZ);

                this->keep_alive();
                this->get_udp_client();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

bool Socks5Connection::check_all_zeros() {
    if (this->dst_addr.size() != 4 || this->dst_port != 0) {
        return false;
    }

    for (auto d : dst_addr) {
        if (d != 0) {
            return false;
        }
    }

    return true;
}

void Socks5Connection::set_client_endpoint() {
    char ipv4[16] = {'\0'};
    std::snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", dst_addr[0], dst_addr[1],
                  dst_addr[2], dst_addr[3]);
    if (std::strcmp(ipv4, "0.0.0.0") == 0) {
        std::strcpy(ipv4, "127.0.0.1");
    }
    client_endpoint =
        asio::ip::udp::endpoint(asio::ip::make_address(ipv4), dst_port);
}

void Socks5Connection::set_destination_endpoint() {
    char ipv4[16] = {'\0'};
    std::snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", dst_addr[0], dst_addr[1],
                  dst_addr[2], dst_addr[3]);
    dst_endpoint =
        asio::ip::udp::endpoint(asio::ip::make_address(ipv4), dst_port);
}

void Socks5Connection::get_udp_client() {
    auto self = shared_from_this();
    udp_socket->async_receive_from(
        asio::buffer(client_buffer.data(), client_buffer.size()),
        sender_endpoint, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                this->udp_length = length;
                SPDLOG_DEBUG(
                    "UDP Client {}:{} -> Proxy {}.{}.{}.{}:{} Data Length = {}",
                    this->sender_endpoint.address().to_string(),
                    this->sender_endpoint.port(),
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                    this->udp_length);

                if (this->check_all_zeros()) {
                    this->client_endpoint = this->sender_endpoint;
                } else {
                    this->set_client_endpoint();
                }

                this->keep_alive();
                this->send_udp_to_dst();
            } else {
                SPDLOG_DEBUG("Failed to receive UDP message from client");
                this->stop();
            }
        });
}

void Socks5Connection::receive_udp_message() {
    auto self = shared_from_this();
    udp_socket->async_receive_from(
        asio::buffer(client_buffer.data(), client_buffer.size()),
        sender_endpoint, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                this->keep_alive();
                this->udp_length = length;

                if (this->sender_endpoint == this->client_endpoint) {
                    SPDLOG_TRACE(
                        "UDP Client {}.{} -> Proxy {}.{}.{}.{}:{} Data Length "
                        "= {}",
                        this->client_endpoint.address().to_string(),
                        this->client_endpoint.port(),
                        static_cast<int16_t>(this->bnd_addr[0]),
                        static_cast<int16_t>(this->bnd_addr[1]),
                        static_cast<int16_t>(this->bnd_addr[2]),
                        static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                        length);

                    this->send_udp_to_dst();
                } else if (this->sender_endpoint == this->dst_endpoint) {
                    SPDLOG_TRACE(
                        "UDP Server {}.{} -> Proxy {}.{}.{}.{}:{} Data Length "
                        "= {}",
                        this->dst_endpoint.address().to_string(),
                        this->dst_endpoint.port(),
                        static_cast<int16_t>(this->bnd_addr[0]),
                        static_cast<int16_t>(this->bnd_addr[1]),
                        static_cast<int16_t>(this->bnd_addr[2]),
                        static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                        length);

                    this->send_udp_to_client();
                } else {
                    // unkown vistor (ignore)
                    this->receive_udp_message();
                }
            } else {
                SPDLOG_DEBUG("Failed to receive UDP message");
                this->stop();
            }
        });
}

void Socks5Connection::send_udp_to_dst() {
    if (udp_length <= 4) {
        SPDLOG_WARN("Udp Associate Header Length Error");
        this->stop();
        return;
    }

    std::memcpy(&this->udp_rsv, this->client_buffer.data(),
                sizeof(this->udp_rsv));
    this->udp_rsv = ntohs(this->udp_rsv);
    if (this->udp_rsv != 0x0000) {
        SPDLOG_WARN("Udp Associate RSV Not Zero");
        this->stop();
        return;
    }

    std::memcpy(&this->frag, this->client_buffer.data() + 2,
                sizeof(this->frag));
    if (this->frag != 0) {
        SPDLOG_WARN("Udp Associate Not Support Splice Process");
        this->stop();
        return;
    }

    std::memcpy(&this->reply_atyp, this->client_buffer.data() + 3,
                sizeof(this->reply_atyp));

    switch (this->reply_atyp) {
        case SocksV5::ReplyATYP::Ipv4:
            if (this->udp_length <= 10) {
                SPDLOG_WARN("Udp Associate Ipv4 Length Error");
                this->stop();
                return;
            }
            std::memcpy(this->dst_addr.data(), this->client_buffer.data() + 4,
                        4);
            std::memcpy(&this->dst_port, this->client_buffer.data() + 8,
                        sizeof(this->dst_port));
            this->dst_port = ntohs(this->dst_port);

            this->udp_length -= 10;
            std::memmove(this->client_buffer.data(),
                         this->client_buffer.data() + 10, this->udp_length);

            break;

        case SocksV5::ReplyATYP::Ipv6:

            break;

        case SocksV5::ReplyATYP::DoMainName:

            break;

        default:
            this->stop();
            return;
    }

    this->set_destination_endpoint();

    auto self = shared_from_this();
    udp_socket->async_send_to(
        asio::buffer(this->client_buffer.data(), this->udp_length),
        dst_endpoint, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Proxy {}.{}.{}.{}:{} -> UDP Server {}:{} Data Length "
                    "= {}",
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                    this->dst_endpoint.address().to_string(),
                    this->dst_endpoint.port(), length);

                this->keep_alive();
                this->receive_udp_message();
            } else {
                SPDLOG_WARN("Failed to send message to UDP Server {}:{}",
                            this->dst_endpoint.address().to_string(),
                            this->dst_endpoint.port());
                this->stop();
            }
        });
}

void Socks5Connection::send_udp_to_client() {
    if (this->udp_length + 10 > this->client_buffer.size()) {
        this->client_buffer.resize(2 * this->client_buffer.size());
    }

    // move data to back
    std::memmove(this->client_buffer.data() + 10, this->client_buffer.data(),
                 this->udp_length);

    this->reply_atyp = SocksV5::ReplyATYP::Ipv4;

    // add UDP request header
    std::memcpy(this->client_buffer.data(), &this->udp_rsv,
                sizeof(this->udp_rsv));
    std::memcpy(this->client_buffer.data() + 2, &this->frag,
                sizeof(this->frag));
    std::memcpy(this->client_buffer.data() + 3, &this->reply_atyp,
                sizeof(this->reply_atyp));
    std::memcpy(this->client_buffer.data() + 4, this->dst_addr.data(), 4);
    this->dst_port = htons(this->dst_port);
    std::memcpy(this->client_buffer.data() + 8, &this->dst_port,
                sizeof(this->dst_port));

    // add header length
    this->udp_length += 10;

    auto self = shared_from_this();
    udp_socket->async_send_to(
        asio::buffer(this->client_buffer.data(), this->udp_length),
        client_endpoint,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Proxy {}.{}.{}.{}:{} -> UDP Client {}:{} Data Length "
                    "= {}",
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                    this->client_endpoint.address().to_string(),
                    this->client_endpoint.port(), this->udp_length);

                this->keep_alive();
                this->receive_udp_message();
            } else {
                SPDLOG_WARN("Failed to send message to UDP Client {}:{}",
                            this->client_endpoint.address().to_string(),
                            this->client_endpoint.port());
                this->stop();
            }
        });
}

void Socks5Connection::reply_connect_result() {
    std::array<asio::mutable_buffer, 6> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&rep, 1), asio::buffer(&rsv, 1),
         asio::buffer(&reply_atyp, 1), asio::buffer(bnd_addr.data(), 4),
         asio::buffer(&bnd_port, 2)}};

    auto self = shared_from_this();
    asio::async_write(
        socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', REP "
                    "= X'{:02x}', RSV = X'{:02x}' "
                    "ATYP = X'{:02x}', BND.ADDR = {}.{}.{}.{}, BND.PORT = {}]",
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->rep),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->reply_atyp),
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port);
                // prepare buffer
                this->client_buffer.resize(BUFSIZ);
                this->dst_buffer.resize(BUFSIZ);

                this->keep_alive();
                // add two async task
                this->read_from_client();
                this->read_from_dst();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::read_from_client() {
    auto self = shared_from_this();
    socket.async_read_some(
        asio::buffer(client_buffer.data(), client_buffer.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} Data Length = {}",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->local_host, this->local_port, length);

                this->keep_alive();
                this->send_to_dst(length);
            } else {
                SPDLOG_TRACE("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

void Socks5Connection::send_to_dst(size_t write_length) {
    auto self = shared_from_this();
    asio::async_write(
        dst_socket, asio::buffer(client_buffer.data(), write_length),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Proxy {}.{}.{}.{}:{} -> Server {}.{}.{}.{}:{} Data Length "
                    "= {}",
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port,
                    length);

                this->keep_alive();
                this->read_from_client();
            } else {
                SPDLOG_TRACE("Server {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
                this->stop();
            }
        });
}

void Socks5Connection::read_from_dst() {
    auto self = shared_from_this();
    dst_socket.async_read_some(
        asio::buffer(dst_buffer.data(), dst_buffer.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Server {}.{}.{}.{}:{} -> Proxy {}.{}.{}.{}:{} Data Length "
                    "= {}",
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port,
                    static_cast<int16_t>(this->bnd_addr[0]),
                    static_cast<int16_t>(this->bnd_addr[1]),
                    static_cast<int16_t>(this->bnd_addr[2]),
                    static_cast<int16_t>(this->bnd_addr[3]), this->bnd_port,
                    length);

                this->keep_alive();
                this->send_to_client(length);
            } else {
                SPDLOG_TRACE("Server {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
                this->stop();
            }
        });
}

void Socks5Connection::send_to_client(size_t write_length) {
    auto self = shared_from_this();
    asio::async_write(
        socket, asio::buffer(dst_buffer.data(), write_length),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} Data Length = {}",
                    this->local_host, this->local_port,
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    length);

                this->keep_alive();
                this->read_from_dst();
            } else {
                SPDLOG_TRACE("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->stop();
            }
        });
}

std::string Socks5Connection::To16(const std::vector<uint8_t>& ipv6_addr) {
    char ipv6[40] = {'\0'};
    std::snprintf(
        ipv6, sizeof(ipv6),
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%"
        "02x%02x",
        ipv6_addr[0], ipv6_addr[1], ipv6_addr[2], ipv6_addr[3], ipv6_addr[4],
        ipv6_addr[5], ipv6_addr[6], ipv6_addr[7], ipv6_addr[8], ipv6_addr[9],
        ipv6_addr[10], ipv6_addr[11], ipv6_addr[12], ipv6_addr[13],
        ipv6_addr[14], ipv6_addr[15]);
    return std::string(ipv6);
}

std::string Socks5Connection::To4(const std::vector<uint8_t>& ipv4_addr) {
    char ipv4[16] = {'\0'};
    std::snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", ipv4_addr[0], ipv4_addr[1],
                  ipv4_addr[2], ipv4_addr[3]);
    return std::string(ipv4);
}
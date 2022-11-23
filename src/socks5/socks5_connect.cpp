#include "socks5/socks5_connect.h"

Socks5Connection::Socks5Connection(asio::io_context& ioc_,
                                   asio::ip::tcp::socket socket_)
    : ioc(ioc_), socket(std::move(socket_)), dst_socket(ioc_) {
    if (socket.is_open()) {
        try {
            SPDLOG_DEBUG("New Connection {}:{}",
                         socket.remote_endpoint().address().to_string(),
                         socket.remote_endpoint().port());
            uint8_t addr[4];
            std::sscanf(socket.remote_endpoint().address().to_string().c_str(),
                        "%hhu.%hhu.%hhu.%hhu", &addr[0], &addr[1], &addr[2],
                        &addr[3]);
            cli_addr = {addr[0], addr[1], addr[2], addr[3]};
            cli_port = socket.remote_endpoint().port();
        } catch (asio::system_error& ec) {
            SPDLOG_DEBUG("Client Disconnected");
            socket.close();
        }
    }
}

void Socks5Connection::start() {
    if (!socket.is_open()) return;
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&nmethods, 1)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "NMETHODS = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->nmethods));
                this->methods.resize(this->nmethods);
                this->get_methods_list();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::get_methods_list() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->methods.data(), this->methods.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [METHODS "
                    "={:Xpn}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    spdlog::to_hex(this->methods.begin(), this->methods.end()));
                this->method = this->choose_method();
                this->reply_support_method();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
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
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "METHOD = X'{:02x}']",
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->method));

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
                        break;
                }

            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::get_username_length() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&ulen, 1)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', ULEN "
                    "= {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
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
            }
        });
}

void Socks5Connection::get_username_content() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->uname.data(), this->uname.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [UNAME = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    std::string(this->uname.begin(), this->uname.end()));

                this->get_password_length();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::get_password_length() {
    std::array<asio::mutable_buffer, 1> buf = {{asio::buffer(&plen, 1)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [PLEN = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
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
            }
        });
}

void Socks5Connection::get_password_content() {
    auto self = shared_from_this();
    asio::async_read(
        socket, asio::buffer(this->passwd.data(), this->passwd.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [PASSWD = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    std::string(this->passwd.begin(), this->passwd.end()));

                this->auth_and_respond();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
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
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', "
                    "STATUS = X'{:02x}']",
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->status));

                if (this->status == SocksV5::ReplyAuthStatus::Success) {
                    this->get_socks_request();
                }
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::get_socks_request() {
    std::array<asio::mutable_buffer, 4> buf = {
        {asio::buffer(&ver, 1), asio::buffer(&cmd, 1), asio::buffer(&rsv, 1),
         asio::buffer(&request_atyp, 1)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [VER = "
                    "X'{:02x}', CMD "
                    "= X'{:02x}, RSV = X'{:02x}', ATYP = X'{:02x}']",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->cmd),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->request_atyp));
                this->get_dst_information();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::get_dst_information() {
    reply_atyp = SocksV5::ReplyATYP::Ipv4;    // reply 只支持 ipv4
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
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                // 网络字节序转主机字节序
                this->dst_port = ntohs(this->dst_port);

                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [DST.ADDR = "
                    "{}.{}.{}.{}, DST.PORT = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port);
                this->connect_dst_host();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::parse_ipv6() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(dst_addr.data(), dst_addr.size()),
         asio::buffer(&dst_port, 2)}};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                // 网络字节序转主机字节序
                this->dst_port = ntohs(this->dst_port);
                std::string ipv6_host = To16(this->dst_addr);

                asio::ip::tcp::resolver resolver(this->ioc);
                auto endpoints =
                    resolver.resolve(ipv6_host, std::to_string(this->dst_port));

                std::string host = endpoints->endpoint().address().to_string();
                uint8_t addr[4];
                std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0],
                            &addr[1], &addr[2], &addr[3]);

                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : [DST.ADDR = "
                    "{}, DST.PORT = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(), std::move(ipv6_host),
                    this->dst_port);
                this->dst_addr = {addr[0], addr[1], addr[2], addr[3]};
                this->connect_dst_host();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::parse_domain() { parse_domain_length(); }

void Socks5Connection::parse_domain_length() {
    std::array<asio::mutable_buffer, 1> buf = {
        asio::buffer(dst_addr.data(), 1)};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {}.{}.{}.{}:{} -> Proxy {}:{} DATA : "
                    "[DOMAIN_LENGTH = {}]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->dst_addr[0]));
                this->parse_domain_content(this->dst_addr[0]);
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
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
            }
        });
}

void Socks5Connection::parse_port() {
    std::array<asio::mutable_buffer, 1> buf = {asio::buffer(&dst_port, 2)};
    auto self = shared_from_this();
    asio::async_read(
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                // 网络字节序转主机字节序
                this->dst_port = ntohs(this->dst_port);

                std::string domain;
                for (auto ch : dst_addr) {
                    domain.push_back(static_cast<char>(ch));
                }

                asio::ip::tcp::resolver resolver(this->ioc);
                auto endpoints =
                    resolver.resolve(domain, std::to_string(this->dst_port));

                std::string host = endpoints->endpoint().address().to_string();
                uint8_t addr[4];
                std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0],
                            &addr[1], &addr[2], &addr[3]);

                SPDLOG_DEBUG(
                    "Client {}:{} -> Proxy {}:{} DATA : [DOMAIN_CONTENT = "
                    "{}({}.{}.{}.{}:{})]",
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(), domain,
                    static_cast<int16_t>(addr[0]),
                    static_cast<int16_t>(addr[1]),
                    static_cast<int16_t>(addr[2]),
                    static_cast<int16_t>(addr[3]), this->dst_port);

                this->dst_addr = {addr[0], addr[1], addr[2], addr[3]};
                this->connect_dst_host();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
            }
        });
}

void Socks5Connection::connect_dst_host() {
    auto self = shared_from_this();
    std::string host = To4(dst_addr);

    dst_socket.async_connect(
        asio::ip::tcp::endpoint(asio::ip::address::from_string(std::move(host)),
                                dst_port),
        [this, self](asio::error_code ec) {
            if (!ec) {
                // 连接成功
                this->rep = SocksV5::ReplyREP::Succeeded;
                this->bnd_port = this->dst_socket.local_endpoint().port();
                std::string host =
                    this->dst_socket.local_endpoint().address().to_string();
                uint8_t addr[4];
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

                this->reply_connect_result();
            } else {
                SPDLOG_DEBUG("Server {}.{}.{}.{}:{} Connection Failed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
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
        socket, buf, [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {}:{} -> Client {}.{}.{}.{}:{} DATA : [VER = "
                    "X'{:02x}', REP "
                    "= X'{:02x}', RSV = X'{:02x}' "
                    "ATYP = X'{:02x}', BND.ADDR = {}.{}.{}.{}, BND.PORT = {}]",
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
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
                    static_cast<int16_t>(this->bnd_addr[3]), this->dst_port);
                // 准备缓冲区
                this->client_buffer.resize(BUFSIZ);
                this->dst_buffer.resize(BUFSIZ);

                // 准备两个方向的异步任务
                this->read_from_client();
                this->read_from_dst();
            } else {
                SPDLOG_DEBUG("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
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
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(), length);
                this->send_to_dst(length);
            } else {
                SPDLOG_TRACE("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->dst_socket.close();
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
                    "Proxy {}:{} -> Server {}.{}.{}.{}:{} Data Length = {}",
                    this->dst_socket.local_endpoint().address().to_string(),
                    this->dst_socket.local_endpoint().port(),
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port,
                    length);
                this->read_from_client();
            } else {
                SPDLOG_TRACE("Server {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
                this->socket.close();
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
                    "Server {}.{}.{}.{}:{} -> Proxy {}:{} Data Length = {}",
                    static_cast<int16_t>(this->dst_addr[0]),
                    static_cast<int16_t>(this->dst_addr[1]),
                    static_cast<int16_t>(this->dst_addr[2]),
                    static_cast<int16_t>(this->dst_addr[3]), this->dst_port,
                    this->dst_socket.local_endpoint().address().to_string(),
                    this->dst_socket.local_endpoint().port(), length);
                this->send_to_client(length);
            } else {
                SPDLOG_TRACE("Server {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->dst_addr[0]),
                             static_cast<int16_t>(this->dst_addr[1]),
                             static_cast<int16_t>(this->dst_addr[2]),
                             static_cast<int16_t>(this->dst_addr[3]),
                             this->dst_port);
                this->socket.close();
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
                    this->socket.local_endpoint().address().to_string(),
                    this->socket.local_endpoint().port(),
                    static_cast<int16_t>(this->cli_addr[0]),
                    static_cast<int16_t>(this->cli_addr[1]),
                    static_cast<int16_t>(this->cli_addr[2]),
                    static_cast<int16_t>(this->cli_addr[3]), this->cli_port,
                    length);
                this->read_from_dst();
            } else {
                SPDLOG_TRACE("Client {}.{}.{}.{}:{} Closed",
                             static_cast<int16_t>(this->cli_addr[0]),
                             static_cast<int16_t>(this->cli_addr[1]),
                             static_cast<int16_t>(this->cli_addr[2]),
                             static_cast<int16_t>(this->cli_addr[3]),
                             this->cli_port);
                this->dst_socket.close();
            }
        });
}

std::string Socks5Connection::To16(const std::vector<uint8_t>& ipv6_addr) {
    char ipv6[40] = {'\0'};
    snprintf(ipv6, sizeof(ipv6),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%"
             "02x%02x",
             ipv6_addr[0], ipv6_addr[1], ipv6_addr[2], ipv6_addr[3],
             ipv6_addr[4], ipv6_addr[5], ipv6_addr[6], ipv6_addr[7],
             ipv6_addr[8], ipv6_addr[9], ipv6_addr[10], ipv6_addr[11],
             ipv6_addr[12], ipv6_addr[13], ipv6_addr[14], ipv6_addr[15]);
    return std::string(ipv6);
}

std::string Socks5Connection::To4(const std::vector<uint8_t>& ipv4_addr) {
    char ipv4[16] = {'\0'};
    snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", ipv4_addr[0], ipv4_addr[1],
             ipv4_addr[2], ipv4_addr[3]);
    return std::string(ipv4);
}
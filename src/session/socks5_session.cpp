#include "session/socks5_session.h"

Socks5Session::Socks5Session(asio::io_context& ioc_)
    : ioc(ioc_),
      udp_resolver(ioc_),
      socket(ioc_),
      dst_socket(ioc_),
      deadline(ioc_) {
    deadline.expires_at(asio::steady_timer::time_point::max());
}

asio::ip::tcp::socket& Socks5Session::get_socket() { return this->socket; }

void Socks5Session::start() {
    try {
        this->local_endpoint = socket.local_endpoint();
        this->tcp_cli_endpoint = socket.remote_endpoint();

        SPDLOG_DEBUG("New Client Connection {}",
                     convert::format_address(this->tcp_cli_endpoint));

        this->check_deadline();
        this->keep_alive();
        this->get_version_and_nmethods();
    } catch (const asio::system_error& e) {
        SPDLOG_WARN("Socks5 Session Failed to Start : ERR_MSG = [{}]",
                    std::string(e.what()));
        this->stop();
    }
}

void Socks5Session::stop() {
    asio::error_code ignored_ec;
    this->udp_resolver.cancel();
    this->socket.close(ignored_ec);
    this->dst_socket.close(ignored_ec);
    this->deadline.cancel(ignored_ec);
}

void Socks5Session::check_deadline() {
    if (!socket.is_open() && !dst_socket.is_open()) {
        return;
    }

    if (deadline.expiry() <= asio::steady_timer::clock_type::now()) {
        SPDLOG_DEBUG("Client {} Timeout",
                     convert::format_address(this->tcp_cli_endpoint));
        this->stop();
    } else {
        auto self = shared_from_this();
        deadline.async_wait(std::bind(&Socks5Session::check_deadline, self));
    }
}

void Socks5Session::set_timeout(size_t second) { this->timeout = second; }

void Socks5Session::keep_alive() {
    if (this->timeout > 0) {
        SPDLOG_TRACE("Connection Keep Alive");
        deadline.expires_after(asio::chrono::seconds(this->timeout));
    }
}

void Socks5Session::get_version_and_nmethods() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->nmethods, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [VER = "
                    "X'{:02x}', "
                    "NMETHODS = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->nmethods));

                if (this->ver != SocksVersion::V5) {
                    SPDLOG_DEBUG("Unsupported protocol version");
                    this->stop();
                    return;
                }

                this->methods.resize(this->nmethods);
                this->get_methods_list();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_methods_list() {
    auto self = shared_from_this();
    asio::async_read(
        this->socket, asio::buffer(this->methods.data(), this->methods.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [METHODS "
                    "={:Xpn}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    spdlog::to_hex(this->methods.begin(), this->methods.end()));

                this->method = this->choose_method();
                this->reply_support_method();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

SocksV5::Method Socks5Session::choose_method() {
    for (auto&& method : this->methods) {
        if (ServerParser::global_config()->is_supported_method(method)) {
            return method;
        }
    }
    return SocksV5::Method::NoAcceptable;
}

void Socks5Session::reply_support_method() {
    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->method, 1)}};

    auto self = shared_from_this();
    asio::async_write(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {} -> Client {} DATA : [VER = "
                    "X'{:02x}', "
                    "METHOD = X'{:02x}']",
                    convert::format_address(this->local_endpoint),
                    convert::format_address(this->tcp_cli_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->method));

                switch (this->method) {
                    case SocksV5::Method::NoAuth: {
                        this->do_no_auth();
                    } break;

                    case SocksV5::Method::UserPassWd: {
                        this->do_username_password_auth();
                    } break;

                    case SocksV5::Method::GSSAPI: {
                        // not supported
                    } break;

                    case SocksV5::Method::NoAcceptable: {
                        this->stop();
                    } break;
                }

            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::do_no_auth() { this->get_request_from_client(); }

void Socks5Session::do_username_password_auth() { this->get_username_length(); }

void Socks5Session::get_username_length() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->ulen, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [VER = "
                    "X'{:02x}', ULEN = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->ulen));

                this->uname.resize(static_cast<std::size_t>(this->ulen));
                this->get_username_content();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_username_content() {
    auto self = shared_from_this();
    asio::async_read(
        this->socket, asio::buffer(this->uname.data(), this->uname.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [UNAME = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    std::string(this->uname.begin(), this->uname.end()));

                this->get_password_length();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_password_length() {
    std::array<asio::mutable_buffer, 1> buf = {{asio::buffer(&plen, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG("Client {} -> Proxy {} DATA : [PLEN = {}]",
                             convert::format_address(this->tcp_cli_endpoint),
                             convert::format_address(this->local_endpoint),
                             static_cast<int16_t>(this->plen));

                this->passwd.resize(static_cast<std::size_t>(this->plen));
                this->get_password_content();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_password_content() {
    auto self = shared_from_this();
    asio::async_read(
        this->socket, asio::buffer(this->passwd.data(), this->passwd.size()),
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [PASSWD = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    std::string(this->passwd.begin(), this->passwd.end()));

                this->do_auth_and_reply();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::do_auth_and_reply() {
    if (ServerParser::global_config()->check_username(
            std::string(this->uname.begin(), this->uname.end())) &&
        ServerParser::global_config()->check_password(
            std::string(this->passwd.begin(), this->passwd.end()))) {
        this->status = SocksV5::ReplyAuthStatus::Success;
    } else {
        this->status = SocksV5::ReplyAuthStatus::Failure;
    }

    std::array<asio::const_buffer, 2> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->status, 1)}};

    auto self = shared_from_this();
    asio::async_write(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {} -> Client {} DATA : [VER = "
                    "X'{:02x}', STATUS = X'{:02x}']",
                    convert::format_address(this->local_endpoint),
                    convert::format_address(this->tcp_cli_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->status));

                if (this->status == SocksV5::ReplyAuthStatus::Success) {
                    this->get_request_from_client();
                } else {
                    this->stop();
                }
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_request_from_client() {
    std::array<asio::mutable_buffer, 4> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->cmd, 1),
         asio::buffer(&this->rsv, 1), asio::buffer(&this->request_atyp, 1)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [VER = X'{:02x}', CMD "
                    "= X'{:02x}, RSV = X'{:02x}', ATYP = X'{:02x}']",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->cmd),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->request_atyp));

                this->get_dst_information();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_dst_information() {
    switch (this->request_atyp) {
        case SocksV5::RequestATYP::Ipv4: {
            this->dst_addr.resize(4);
            this->resolve_ipv4();
        } break;

        case SocksV5::RequestATYP::Ipv6: {
            dst_addr.resize(16);
            this->resolve_ipv6();
        } break;

        case SocksV5::RequestATYP::DoMainName: {
            this->dst_addr.resize(UINT8_MAX);
            this->resolve_domain();
        } break;

        default: {
            SPDLOG_WARN("Unkown Request Atyp");
            this->reply_and_stop(SocksV5::ReplyREP::AddrTypeNotSupported);
        } break;
    }
}

void Socks5Session::resolve_ipv4() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(this->dst_addr.data(), this->dst_addr.size()),
         asio::buffer(&this->dst_port, 2)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // network octet order convert to host octet order
                this->dst_port = ntohs(this->dst_port);

                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [DST.ADDR = "
                    "{}, DST.PORT = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv4),
                    this->dst_port);

                this->execute_command();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::resolve_ipv6() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(this->dst_addr.data(), this->dst_addr.size()),
         asio::buffer(&this->dst_port, 2)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // network octet order convert to host octet order
                this->dst_port = ntohs(this->dst_port);

                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [DST.ADDR "
                    "= {}, DST.PORT = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv6),
                    this->dst_port);

                this->execute_command();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::resolve_domain() { this->resolve_domain_length(); }

void Socks5Session::resolve_domain_length() {
    std::array<asio::mutable_buffer, 1> buf = {
        asio::buffer(this->dst_addr.data(), 1)};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : "
                    "[DOMAIN_LENGTH = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    static_cast<int16_t>(this->dst_addr[0]));

                this->dst_addr.resize(
                    static_cast<std::size_t>(this->dst_addr[0]));
                this->resolve_domain_content();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::resolve_domain_content() {
    std::array<asio::mutable_buffer, 2> buf = {
        {asio::buffer(this->dst_addr.data(), this->dst_addr.size()),
         asio::buffer(&this->dst_port, 2)}};

    auto self = shared_from_this();
    asio::async_read(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                // network octet order convert to host octet order
                this->dst_port = ntohs(this->dst_port);

                SPDLOG_DEBUG(
                    "Client {} -> Proxy {} DATA : [DST.ADDR = "
                    "{}, DST.PORT = {}]",
                    convert::format_address(this->tcp_cli_endpoint),
                    convert::format_address(this->local_endpoint),
                    convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
                    this->dst_port);

                this->execute_command();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::execute_command() {
    switch (this->cmd) {
        case SocksV5::RequestCMD::Connect: {
            this->set_connect_endpoint();
        } break;

        case SocksV5::RequestCMD::Bind: {
            /*not supported*/
            this->reply_and_stop(SocksV5::ReplyREP::CommandNotSupported);
        } break;

        case SocksV5::RequestCMD::UdpAssociate: {
            this->set_udp_associate_endpoint();
        } break;

        default: {
            this->reply_and_stop(SocksV5::ReplyREP::CommandNotSupported);
        } break;
    }
}

void Socks5Session::set_connect_endpoint() {
    switch (this->request_atyp) {
        case SocksV5::RequestATYP::Ipv4: {
            this->tcp_dst_endpoint = asio::ip::tcp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv4)),
                this->dst_port);

            this->connect_dst_host();
        } break;

        case SocksV5::RequestATYP::Ipv6: {
            this->tcp_dst_endpoint = asio::ip::tcp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv6)),
                this->dst_port);

            this->connect_dst_host();
        } break;

        case SocksV5::RequestATYP::DoMainName: {
            this->async_dns_reslove();
        } break;
    }
}

void Socks5Session::set_udp_associate_endpoint() {
    switch (this->request_atyp) {
        case SocksV5::RequestATYP::Ipv4: {
            this->udp_cli_endpoint = asio::ip::udp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv4)),
                this->dst_port);

            this->reply_udp_associate();
        } break;

        case SocksV5::RequestATYP::Ipv6: {
            this->udp_cli_endpoint = asio::ip::udp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv6)),
                this->dst_port);

            this->reply_udp_associate();
        } break;

        case SocksV5::RequestATYP::DoMainName: {
            this->async_udp_dns_reslove();
        } break;
    }
}

void Socks5Session::async_udp_dns_reslove() {
    auto self = shared_from_this();
    this->udp_resolver.async_resolve(
        convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
        std::to_string(this->dst_port),
        [this, self](asio::error_code ec,
                     const asio::ip::udp::resolver::results_type& result) {
            if (!ec) {
                this->resolve_results = result;

                // use first endpoint
                this->udp_cli_endpoint =
                    this->resolve_results.begin()->endpoint();

                SPDLOG_DEBUG(
                    "Reslove Domain {} {} result sets in total",
                    convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
                    this->resolve_results.size());

                this->reply_udp_associate();
            } else {
                SPDLOG_WARN(
                    "Failed to Reslove Domain {}, ERR_MSG = [{}]",
                    convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
                    ec.message());

                this->reply_and_stop(SocksV5::ReplyREP::HostUnreachable);
            }
        });
}

void Socks5Session::reply_udp_associate() {
    this->rep = SocksV5::ReplyREP::Succeeded;
    try {
        if (this->udp_cli_endpoint.address().is_v4()) {
            this->reply_atyp = SocksV5::ReplyATYP::Ipv4;
            this->udp_socket.reset(new asio::ip::udp::socket(
                this->ioc, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)));
            this->bnd_addr.resize(4);
            std::memcpy(this->bnd_addr.data(),
                        this->udp_socket->local_endpoint()
                            .address()
                            .to_v4()
                            .to_bytes()
                            .data(),
                        4);
        } else {
            this->reply_atyp = SocksV5::ReplyATYP::Ipv6;
            this->udp_socket.reset(new asio::ip::udp::socket(
                this->ioc, asio::ip::udp::endpoint(asio::ip::udp::v6(), 0)));
            this->bnd_addr.resize(16);
            std::memcpy(this->bnd_addr.data(),
                        this->udp_socket->local_endpoint()
                            .address()
                            .to_v6()
                            .to_bytes()
                            .data(),
                        16);
        }

        this->udp_bnd_endpoint = this->udp_socket->local_endpoint();

        // host octet order convert to network octet order
        this->bnd_port = htons(this->udp_bnd_endpoint.port());

    } catch (const asio::system_error& e) {
        SPDLOG_WARN("Failed to reply udp associate, ERR_MSG = [{}]",
                    std::string(e.what()));
    }

    std::array<asio::mutable_buffer, 6> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->rep, 1),
         asio::buffer(&this->rsv, 1), asio::buffer(&this->reply_atyp, 1),
         asio::buffer(this->bnd_addr.data(), this->bnd_addr.size()),
         asio::buffer(&this->bnd_port, 2)}};

    auto self = shared_from_this();
    asio::async_write(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {} -> Client {} DATA : [VER = "
                    "X'{:02x}', REP = X'{:02x}', RSV = X'{:02x}' "
                    "ATYP = X'{:02x}', BND.ADDR = {}, BND.PORT = {}]",
                    convert::format_address(this->local_endpoint),
                    convert::format_address(this->tcp_cli_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->rep),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->reply_atyp),
                    this->udp_bnd_endpoint.address().to_string(),
                    this->udp_bnd_endpoint.port());

                this->client_buffer.resize(BUFSIZ);

                this->get_udp_client();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::get_udp_client() {
    auto self = shared_from_this();
    this->udp_socket->async_receive_from(
        asio::buffer(this->client_buffer.data(), this->client_buffer.size()),
        this->sender_endpoint,
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                this->udp_length = length;

                SPDLOG_DEBUG("UDP Client {} -> Proxy {} Data Length = {}",
                             convert::format_address(this->sender_endpoint),
                             convert::format_address(this->udp_bnd_endpoint),
                             this->udp_length);

                if (this->check_sender_endpoint()) {
                    this->parse_udp_message();
                } else {
                    this->get_udp_client();
                }
            } else {
                SPDLOG_DEBUG("Failed to receive UDP message from client");
                this->stop();
            }
        });
}

bool Socks5Session::check_sender_endpoint() {
    if (this->check_all_zeros()) {
        this->udp_cli_endpoint = this->sender_endpoint;
        return true;
    }

    switch (this->request_atyp) {
        case SocksV5::RequestATYP::Ipv4: {
            if (this->check_dst_addr_all_zeros()) {
                // this->udp_cli_endpoint =
                //     asio::ip::udp::endpoint(asio::ip::address_v4::loopback(),
                //                             this->udp_cli_endpoint.port());
                this->udp_cli_endpoint = this->sender_endpoint;
                return true;
            }
        } break;

        case SocksV5::RequestATYP::Ipv6: {
            if (this->check_dst_addr_all_zeros()) {
                // this->udp_cli_endpoint =
                //     asio::ip::udp::endpoint(asio::ip::address_v6::loopback(),
                //                             this->udp_cli_endpoint.port());
                this->udp_cli_endpoint = this->sender_endpoint;
                return true;
            }
        } break;

        case SocksV5::RequestATYP::DoMainName: {
            for (auto iter : this->resolve_results) {
                if (iter.endpoint() == this->sender_endpoint) {
                    return true;
                }
            }
            return false;
        } break;
    };

    return this->udp_cli_endpoint == this->sender_endpoint;
}

bool Socks5Session::check_all_zeros() {
    return this->udp_cli_endpoint ==
           asio::ip::udp::endpoint(this->udp_cli_endpoint.protocol(), 0);
}

bool Socks5Session::check_dst_addr_all_zeros() {
    for (auto d : this->dst_addr) {
        if (d != 0) {
            return false;
        }
    }

    return true;
}

void Socks5Session::parse_udp_message() {
    if (this->udp_length <= 4) {
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
        case SocksV5::ReplyATYP::Ipv4: {
            if (this->udp_length <= 10) {
                SPDLOG_WARN("Udp Associate Ipv4 Length Error");
                this->stop();
                return;
            }

            this->dst_addr.resize(4);
            std::memcpy(this->dst_addr.data(), this->client_buffer.data() + 4,
                        4);
            std::memcpy(&this->dst_port, this->client_buffer.data() + 8,
                        sizeof(this->dst_port));
            this->dst_port = ntohs(this->dst_port);

            this->udp_dst_endpoint = asio::ip::udp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv4)),
                this->dst_port);

            this->udp_length -= 10;
            std::memmove(this->client_buffer.data(),
                         this->client_buffer.data() + 10, this->udp_length);

            this->send_udp_to_dst();
        } break;

        case SocksV5::ReplyATYP::Ipv6: {
            if (this->udp_length <= 18) {
                SPDLOG_WARN("Udp Associate Ipv6 Length Error");
                this->stop();
                return;
            }

            this->dst_addr.resize(16);
            std::memcpy(this->dst_addr.data(), this->client_buffer.data() + 4,
                        16);
            std::memcpy(&this->dst_port, this->client_buffer.data() + 20,
                        sizeof(this->dst_port));
            this->dst_port = ntohs(this->dst_port);

            this->udp_dst_endpoint = asio::ip::udp::endpoint(
                asio::ip::address::from_string(
                    convert::dst_to_string(this->dst_addr, ATyp::Ipv6)),
                this->dst_port);

            this->udp_length -= 22;
            std::memmove(this->client_buffer.data(),
                         this->client_buffer.data() + 22, this->udp_length);

            this->send_udp_to_dst();
        } break;

        case SocksV5::ReplyATYP::DoMainName: {
            this->dst_addr.resize(1 + UINT8_MAX);
            std::memcpy(this->dst_addr.data(), this->client_buffer.data() + 4,
                        sizeof(this->dst_addr[0]));
            uint8_t domain_length = this->dst_addr[0];
            if (this->udp_length <=
                static_cast<size_t>(domain_length + 7)) {    // 4 + 1 + len + 2
                SPDLOG_WARN("Udp Associate DoMainName Length Error");
                this->stop();
                return;
            }

            this->dst_addr.resize(1 + domain_length);
            std::memcpy(this->dst_addr.data() + 1,
                        this->client_buffer.data() + 5, domain_length);
            std::memcpy(&this->dst_port,
                        this->client_buffer.data() + 5 + domain_length,
                        sizeof(this->dst_port));
            this->dst_port = ntohs(this->dst_port);

            this->udp_length -= domain_length + 7;
            std::memmove(this->client_buffer.data(),
                         this->client_buffer.data() + domain_length + 7,
                         this->udp_length);

            this->async_send_udp_message();
        } break;
    }
}

void Socks5Session::async_send_udp_message() {
    auto self = shared_from_this();
    this->udp_resolver.async_resolve(
        std::string(this->dst_addr.begin() + 1, this->dst_addr.end()),
        std::to_string(this->dst_port),
        [this, self](asio::error_code ec,
                     const asio::ip::udp::resolver::results_type& result) {
            if (!ec) {
                this->resolve_results = result;

                SPDLOG_DEBUG("Reslove Domain {} {} result sets in total",
                             std::string(this->dst_addr.begin() + 1,
                                         this->dst_addr.end()),
                             this->resolve_results.size());

                this->try_to_send_by_iterator(this->resolve_results.begin());
            } else {
                SPDLOG_WARN("Failed to Reslove Domain {}, ERR_MSG = [{}]",
                            std::string(this->dst_addr.begin() + 1,
                                        this->dst_addr.end()),
                            ec.message());

                this->stop();
            }
        });
}

void Socks5Session::try_to_send_by_iterator(
    asio::ip::udp::resolver::results_type::const_iterator iter) {
    if (iter == this->resolve_results.end()) {
        this->stop();
        return;
    }

    this->udp_dst_endpoint = iter->endpoint();

    SPDLOG_DEBUG("Try to Send {}",
                 convert::format_address(this->udp_dst_endpoint));

    ++iter;

    auto self = shared_from_this();
    this->udp_socket->async_send_to(
        asio::buffer(this->client_buffer.data(), this->udp_length),
        this->udp_dst_endpoint,
        [this, self, iter](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Proxy {} -> UDP Server {} Data Length = {}",
                             convert::format_address(this->udp_bnd_endpoint),
                             convert::format_address(this->udp_dst_endpoint),
                             length);

                this->keep_alive();
                this->receive_udp_message();
            } else {
                this->try_to_send_by_iterator(iter);
            }
        });
}

void Socks5Session::send_udp_to_dst() {
    auto self = shared_from_this();
    udp_socket->async_send_to(
        asio::buffer(this->client_buffer.data(), this->udp_length),
        this->udp_dst_endpoint,
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Proxy {} -> UDP Server {} Data Length = {}",
                             convert::format_address(this->udp_bnd_endpoint),
                             convert::format_address(this->udp_dst_endpoint),
                             length);

                this->keep_alive();
                this->receive_udp_message();
            } else {
                SPDLOG_WARN("Failed to send message to UDP Server {}",
                            convert::format_address(this->udp_dst_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::send_udp_to_client() {
    this->dst_port = htons(this->dst_port);
    std::array<asio::const_buffer, 5> buf = {
        {asio::buffer(&this->udp_rsv, 2), asio::buffer(&this->frag, 1),
         asio::buffer(&this->reply_atyp, 1),
         asio::buffer(this->dst_addr.data(), this->dst_addr.size()),
         asio::buffer(&this->dst_port, 2)}};

    size_t buf_bytes = 0;
    for (const auto& b : buf) {
        buf_bytes += b.size();
    }

    if (this->udp_length + buf_bytes > this->client_buffer.size()) {
        this->client_buffer.resize(this->udp_length + buf_bytes);
    }

    // user data move data to back
    std::memmove(this->client_buffer.data() + buf_bytes,
                 this->client_buffer.data(), this->udp_length);

    // add header to front
    buf_bytes = 0;
    for (const auto& b : buf) {
        std::memcpy(this->client_buffer.data() + buf_bytes, b.data(), b.size());
        buf_bytes += b.size();
    }

    this->udp_length += buf_bytes;

    auto self = shared_from_this();
    this->udp_socket->async_send_to(
        asio::buffer(this->client_buffer.data(), this->udp_length),
        this->udp_cli_endpoint,
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Proxy {} -> UDP Client {} Data Length = {}",
                             convert::format_address(this->udp_bnd_endpoint),
                             convert::format_address(this->udp_cli_endpoint),
                             length);

                this->keep_alive();
                this->receive_udp_message();
            } else {
                SPDLOG_WARN("Failed to send message to UDP Client {}",
                            convert::format_address(this->udp_cli_endpoint));

                this->stop();
            }
        });
}

void Socks5Session::receive_udp_message() {
    auto self = shared_from_this();
    this->udp_socket->async_receive_from(
        asio::buffer(this->client_buffer.data(), this->client_buffer.size()),
        this->sender_endpoint,
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                this->udp_length = length;

                this->keep_alive();
                if (this->sender_endpoint == this->udp_cli_endpoint) {
                    SPDLOG_TRACE(
                        "UDP Client {} -> Proxy {} Data Length = {}",
                        convert::format_address(this->udp_cli_endpoint),
                        convert::format_address(this->udp_bnd_endpoint),
                        length);

                    this->parse_udp_message();
                } else if (this->sender_endpoint == this->udp_dst_endpoint) {
                    SPDLOG_TRACE(
                        "UDP Server {} -> Proxy {} Data Length = {}",
                        convert::format_address(this->udp_dst_endpoint),
                        convert::format_address(this->udp_bnd_endpoint),
                        length);

                    this->send_udp_to_client();
                } else {
                    // unkown vistor (ignore)
                    this->receive_udp_message();
                }

            } else {
                SPDLOG_WARN("Failed to receive UDP message");
                this->stop();
            }
        });
}

void Socks5Session::connect_dst_host() {
    auto self = shared_from_this();
    this->dst_socket.async_connect(
        this->tcp_dst_endpoint, [this, self](asio::error_code ec) {
            if (!ec) {
                try {
                    this->tcp_bnd_endpoint = this->dst_socket.local_endpoint();
                } catch (const asio::system_error&) {
                    this->reply_and_stop(SocksV5::ReplyREP::ConnRefused);
                    return;
                }

                this->rep = SocksV5::ReplyREP::Succeeded;

                this->set_reply_address(this->tcp_bnd_endpoint);

                SPDLOG_DEBUG("Proxy {} -> Server {} Connection Successed",
                             convert::format_address(this->tcp_bnd_endpoint),
                             convert::format_address(this->tcp_dst_endpoint));

                this->reply_connect_result();
            } else {
                SPDLOG_DEBUG("Server {} Connection Failed",
                             convert::format_address(this->tcp_dst_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::async_dns_reslove() {
    auto self = shared_from_this();
    this->udp_resolver.async_resolve(
        convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
        std::to_string(this->dst_port),
        [this, self](asio::error_code ec,
                     const asio::ip::udp::resolver::results_type& result) {
            if (!ec) {
                this->resolve_results = result;
                SPDLOG_DEBUG(
                    "Reslove Domain {} {} result sets in total",
                    convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
                    this->resolve_results.size());

                this->try_to_connect_by_iterator(this->resolve_results.begin());
            } else {
                SPDLOG_WARN(
                    "Failed to Reslove Domain {}, ERR_MSG = [{}]",
                    convert::dst_to_string(this->dst_addr, ATyp::DoMainName),
                    ec.message());

                this->reply_and_stop(SocksV5::ReplyREP::HostUnreachable);
            }
        });
}

void Socks5Session::try_to_connect_by_iterator(
    asio::ip::udp::resolver::results_type::const_iterator iter) {
    if (iter == this->resolve_results.end()) {
        this->reply_and_stop(SocksV5::ReplyREP::NetworkUnreachable);
        return;
    }

    this->tcp_dst_endpoint = asio::ip::tcp::endpoint(iter->endpoint().address(),
                                                     iter->endpoint().port());

    SPDLOG_DEBUG("Try to Connect {}",
                 convert::format_address(this->tcp_dst_endpoint));

    ++iter;

    auto self = shared_from_this();
    this->dst_socket.async_connect(
        this->tcp_dst_endpoint, [this, self, iter](asio::error_code ec) {
            if (!ec) {
                try {
                    this->tcp_bnd_endpoint = this->dst_socket.local_endpoint();
                } catch (const asio::system_error&) {
                    this->reply_and_stop(SocksV5::ReplyREP::ConnRefused);
                    return;
                }

                this->rep = SocksV5::ReplyREP::Succeeded;

                this->set_reply_address(this->tcp_bnd_endpoint);

                SPDLOG_DEBUG("Proxy {} -> Server {} Connection Successed",
                             convert::format_address(this->tcp_bnd_endpoint),
                             convert::format_address(this->tcp_dst_endpoint));

                this->reply_connect_result();
            } else {
                this->try_to_connect_by_iterator(iter);
            }
        });
}

void Socks5Session::reply_and_stop(SocksV5::ReplyREP rep) {
    this->rep = rep;
    this->reply_atyp = SocksV5::ReplyATYP::Ipv4;
    this->bnd_addr = {0, 0, 0, 0};
    this->bnd_port = 0;

    std::array<asio::const_buffer, 6> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->rep, 1),
         asio::buffer(&this->rsv, 1), asio::buffer(&this->reply_atyp, 1),
         asio::buffer(this->bnd_addr.data(), this->bnd_addr.size()),
         asio::buffer(&this->bnd_port, 2)}};

    auto self = shared_from_this();
    asio::async_write(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {} -> Client {} DATA : [VER = X'{:02x}', REP "
                    "= X'{:02x}, RSV = X'{:02x}', ATYP = X'{:02x}', "
                    "BND.ADDR = {}, BND.PORT = {}]",
                    convert::format_address(this->local_endpoint),
                    convert::format_address(this->tcp_cli_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->rep),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->reply_atyp),
                    convert::dst_to_string(this->bnd_addr, ATyp::Ipv4),
                    this->bnd_port);

                this->stop();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::reply_connect_result() {
    std::array<asio::const_buffer, 6> buf = {
        {asio::buffer(&this->ver, 1), asio::buffer(&this->rep, 1),
         asio::buffer(&this->rsv, 1), asio::buffer(&this->reply_atyp, 1),
         asio::buffer(this->bnd_addr.data(), this->bnd_addr.size()),
         asio::buffer(&this->bnd_port, 2)}};

    auto self = shared_from_this();
    asio::async_write(
        this->socket, buf,
        [this, self](asio::error_code ec, size_t /*bytes_transferred*/) {
            if (!ec) {
                SPDLOG_DEBUG(
                    "Proxy {} -> Client {} DATA : [VER = X'{:02x}', REP "
                    "= X'{:02x}, RSV = X'{:02x}', ATYP = X'{:02x}', "
                    "BND.ADDR = {}, BND.PORT = {}]",
                    convert::format_address(this->local_endpoint),
                    convert::format_address(this->tcp_cli_endpoint),
                    static_cast<int16_t>(this->ver),
                    static_cast<int16_t>(this->rep),
                    static_cast<int16_t>(this->rsv),
                    static_cast<int16_t>(this->reply_atyp),
                    this->tcp_bnd_endpoint.address().to_string(),
                    this->tcp_bnd_endpoint.port());

                this->client_buffer.resize(BUFSIZ);
                this->dst_buffer.resize(BUFSIZ);

                this->keep_alive();

                this->read_from_client();
                this->read_from_dst();
            } else {
                SPDLOG_DEBUG("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::read_from_client() {
    auto self = shared_from_this();
    this->socket.async_read_some(
        asio::buffer(this->client_buffer.data(), this->client_buffer.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Client {} -> Proxy {} Data Length = {}",
                             convert::format_address(this->tcp_cli_endpoint),
                             convert::format_address(this->local_endpoint),
                             length);

                this->keep_alive();
                this->send_to_dst(length);
            } else {
                SPDLOG_TRACE("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::send_to_dst(size_t write_length) {
    auto self = shared_from_this();
    asio::async_write(
        this->dst_socket,
        asio::buffer(this->client_buffer.data(), write_length),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Proxy {} -> Server {} Data Length = {}",
                             convert::format_address(this->tcp_bnd_endpoint),
                             convert::format_address(this->tcp_dst_endpoint),
                             length);

                this->keep_alive();
                this->read_from_client();
            } else {
                SPDLOG_TRACE("Server {} Closed",
                             convert::format_address(this->tcp_dst_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::read_from_dst() {
    auto self = shared_from_this();
    this->dst_socket.async_read_some(
        asio::buffer(this->dst_buffer.data(), this->dst_buffer.size()),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Server {} -> Proxy {} Data Length = {}",
                             convert::format_address(this->tcp_dst_endpoint),
                             convert::format_address(this->tcp_bnd_endpoint),
                             length);

                this->keep_alive();
                this->send_to_client(length);
            } else {
                SPDLOG_TRACE("Server {} Closed",
                             convert::format_address(this->tcp_dst_endpoint));
                this->stop();
            }
        });
}

void Socks5Session::send_to_client(size_t write_length) {
    auto self = shared_from_this();
    asio::async_write(
        this->socket, asio::buffer(this->dst_buffer.data(), write_length),
        [this, self](asio::error_code ec, size_t length) {
            if (!ec) {
                SPDLOG_TRACE("Proxy {} -> Client {} Data Length = {}",
                             convert::format_address(this->local_endpoint),
                             convert::format_address(this->tcp_cli_endpoint),
                             length);

                this->keep_alive();
                this->read_from_dst();
            } else {
                SPDLOG_TRACE("Client {} Closed",
                             convert::format_address(this->tcp_cli_endpoint));
                this->stop();
            }
        });
}
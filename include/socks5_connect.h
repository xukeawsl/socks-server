#pragma once

#include "common.h"
#include "socks5_type.h"

class Socks5Connection : public std::enable_shared_from_this<Socks5Connection> {
public:
    Socks5Connection(asio::io_context& ioc_, asio::ip::tcp::socket socket_)
        : ioc(ioc_), socket(std::move(socket_)), dst_socket(ioc_) {}

    virtual ~Socks5Connection() {}

    void start() {
        std::array<asio::mutable_buffer, 2> buf = {
            {
                asio::buffer(&ver, 1),
                asio::buffer(&nmethods, 1)
            }
        };
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    std::cout << "ver : " << (int)this->ver << std::endl;
                    std::cout << "nmethods : " << (int)this->nmethods << std::endl;
                    this->methods.resize(this->nmethods);
                    this->get_methods_list();
                }
            });
    }

private:
    void get_methods_list() {
        auto self = shared_from_this();
        asio::async_read(socket, asio::buffer(this->methods.data(), this->methods.size()),
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    for (int i = 0; i < this->methods.size(); i++) {
                        std::cout << "method " << (int)this->methods[i] << " is supported\n";
                    }
                    this->method = this->choose_method();
                    this->reply_support_method();
                }
            });
    }

    SocksV5::Method choose_method() {
        for (auto method : this->methods) {
            if (method == SocksV5::Method::NoAuth) {
                return method;
            }
        }
        return SocksV5::Method::NoAcceptable;
    }

    void reply_support_method() {
        std::array<asio::const_buffer, 2> buf = {
            {
                asio::buffer(&ver, 1),
                asio::buffer(&method, 1)
            }
        };
        auto self = shared_from_this();
        asio::async_write(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    std::cout << "successful write reply the support method\n";
                    this->get_socks_request();
                }
            });
    }

    void get_socks_request() {
        std::array<asio::mutable_buffer, 4> buf = {
            {
                asio::buffer(&ver, 1),
                asio::buffer(&cmd, 1),
                asio::buffer(&rsv, 1),
                asio::buffer(&request_atyp, 1)
            }
        };
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    std::cout << "ver : " << (int)this->ver << '\n';
                    std::cout << "cmd : " << (int)this->cmd << '\n';
                    std::cout << "rsv : " << (int)this->rsv << '\n';
                    std::cout << "request atyp : " << (int)this->request_atyp << '\n';
                    this->get_dst_information();
                }
            });
    }

    void get_dst_information() {
        if (request_atyp == SocksV5::RequestATYP::Ipv4) {
            dst_addr.resize(4);
            parse_ipv4();
        } else if (request_atyp == SocksV5::RequestATYP::DoMainName) {
            reply_atyp = SocksV5::ReplyATYPE::Ipv4;   // reply 只支持 ipv4
            dst_addr.resize(UINT8_MAX);
            parse_domain();
        }
    }

    void parse_ipv4() {
        std::array<asio::mutable_buffer, 2> buf = {
            {
                asio::buffer(dst_addr.data(), dst_addr.size()),
                asio::buffer(&dst_port, 2)
            }
        };
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length){
                if (!ec) {
                    std::cout << "dst_addr : "
                              << (int)this->dst_addr[0] << "."
                              << (int)this->dst_addr[1] << "."
                              << (int)this->dst_addr[2] << "."
                              << (int)this->dst_addr[3] << "\n";
                    // 网络字节序转主机字节序
                    this->dst_port = ntohs(this->dst_port);
                
                    std::cout << "dst_port : " << this->dst_port << '\n';
                    this->connect_dst_host();
                }
            });
    }

    void parse_domain() {
        parse_domain_length();
    }

    void parse_domain_length() {
        std::array<asio::mutable_buffer, 1> buf = {asio::buffer(dst_addr.data(), 1)};
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->parse_domain_content(this->dst_addr[0]);
                }
            });
    }

    void parse_domain_content(size_t read_length) {
        std::array<asio::mutable_buffer, 1> buf = {asio::buffer(dst_addr.data(), read_length)};
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->dst_addr.resize(length);
                    this->parse_port();
                }
            });
    }

    void parse_port() {
        std::array<asio::mutable_buffer, 1> buf = 
        {
            asio::buffer(&dst_port, 2)
        };
        auto self = shared_from_this();
        asio::async_read(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    // 网络字节序转主机字节序
                    this->dst_port = ntohs(this->dst_port);

                    std::string domain;
                    for (auto ch : dst_addr) {
                        domain.push_back(static_cast<char>(ch));
                    }

                    std::cout << "domain : " << domain << ' ' << "port : " << this->dst_port << '\n';

                    asio::ip::tcp::resolver resolver(this->ioc);
                    auto endpoints = resolver.resolve(domain, std::to_string(this->dst_port));

                    std::string host = endpoints->endpoint().address().to_string();
                    uint8_t addr[4];
                    std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0], &addr[1], &addr[2], &addr[3]);
                    this->dst_addr = {addr[0], addr[1], addr[2], addr[3]};
                    this->connect_dst_host();
                }
            });
    }

    void connect_dst_host() {
        auto self = shared_from_this();
        std::string host;
        for (int i = 0; i < 4; i++) {
            host += std::to_string((uint16_t)dst_addr[i]);
            if (i != 3) host += ".";
        }
        std::cout << "host : " << host << '\n';
        dst_socket.async_connect(asio::ip::tcp::endpoint(asio::ip::address::from_string(std::move(host)), dst_port),
            [this, self](asio::error_code ec) {
                if (!ec) {
                    std::cout << "successfully connect to dst\n";

                    // 连接成功
                    this->rep = SocksV5::ReplyREP::Succeeded;
                    this->bnd_port = this->dst_socket.local_endpoint().port();
                    std::string host = this->dst_socket.local_endpoint().address().to_string();
                    uint8_t addr[4];
                    std::sscanf(host.c_str(), "%hhu.%hhu.%hhu.%hhu", &addr[0], &addr[1], &addr[2], &addr[3]);
                    this->bnd_addr = {addr[0], addr[1], addr[2], addr[3]};
                    this->reply_connect_result();
                }
            });
    }

    void reply_connect_result() {
        std::array<asio::mutable_buffer, 6> buf = {
            {
                asio::buffer(&ver, 1),
                asio::buffer(&rep, 1),
                asio::buffer(&rsv, 1),
                asio::buffer(&reply_atyp, 1),
                asio::buffer(bnd_addr.data(), 4),
                asio::buffer(&bnd_port, 2)
            }
        };
        auto self = shared_from_this();
        asio::async_write(socket, buf,
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    // 准备缓冲区
                    this->client_buffer.resize(BUFSIZ);
                    this->dst_buffer.resize(BUFSIZ);

                    // 准备两个方向的异步任务
                    this->read_from_client();
                    this->read_from_dst();
                }
            });
    }

    void read_from_client() {
        auto self = shared_from_this();
        socket.async_read_some(asio::buffer(client_buffer.data(), client_buffer.size()),
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->send_to_dst(length);
                }
            });
    }

    void send_to_dst(size_t write_length) {
        auto self = shared_from_this();
        asio::async_write(dst_socket, asio::buffer(client_buffer.data(), write_length),
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->read_from_client();
                }
            });
    }

    void read_from_dst() {
        auto self = shared_from_this();
        dst_socket.async_read_some(asio::buffer(dst_buffer.data(), dst_buffer.size()),
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->send_to_client(length);
                }
            });
    }

    void send_to_client(size_t write_length) {
        auto self = shared_from_this();
        asio::async_write(socket, asio::buffer(dst_buffer.data(), write_length),
            [this, self](asio::error_code ec, size_t length) {
                if (!ec) {
                    this->read_from_dst();
                }
            });
    }

protected:
    asio::io_context& ioc;
    asio::ip::tcp::socket socket;
    asio::ip::tcp::socket dst_socket;
    SocksVersion ver;
    uint8_t rsv;

    /* Auth Step */
    uint8_t nmethods;
    std::vector<SocksV5::Method> methods;

    /* Request Step */
    SocksV5::Method method;
    SocksV5::RequestCMD cmd;
    SocksV5::RequestATYP request_atyp;
    std::vector<uint8_t> dst_addr;
    uint16_t dst_port;

    /* Reply Step */
    SocksV5::ReplyATYPE reply_atyp;
    SocksV5::ReplyREP rep;
    std::vector<uint8_t> bnd_addr;
    uint16_t bnd_port;

    /* Talk Step */
    std::vector<uint8_t> client_buffer;
    std::vector<uint8_t> dst_buffer;
};
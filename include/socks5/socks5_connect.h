#pragma once

#include "common/common.h"
#include "socks5/socks5_type.h"

class Socks5Connection : public std::enable_shared_from_this<Socks5Connection> {
public:
    Socks5Connection(asio::io_context& ioc_, asio::ip::tcp::socket socket_);

    virtual ~Socks5Connection() {}

    void start();

private:
    void get_methods_list();

    SocksV5::Method choose_method();

    void reply_support_method();

    void get_socks_request();

    void get_dst_information();

    void parse_ipv4();

    void parse_domain();

    void parse_domain_length();

    void parse_domain_content(size_t read_length);

    void parse_port();

    void connect_dst_host();

    void reply_connect_result();

    void read_from_client();

    void send_to_dst(size_t write_length);

    void read_from_dst();

    void send_to_client(size_t write_length);

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
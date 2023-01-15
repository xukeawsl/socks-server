#pragma once

#include "common/common.h"
#include "option/parser.h"
#include "socks5/socks5_type.h"

class Socks5Connection : public std::enable_shared_from_this<Socks5Connection> {
public:
    explicit Socks5Connection(asio::io_context& ioc_);

    virtual ~Socks5Connection() {}

    static std::string To16(const std::vector<uint8_t>& ipv6_addr);

    static std::string To4(const std::vector<uint8_t>& ipv4_addr);

    asio::ip::tcp::socket& get_socket();

    void start();

    void set_timeout(size_t second);

private:
    inline void keep_alive();

    void check_deadline();

    void stop();

    //  +----+----------+----------+
    //  |VER | NMETHODS | METHODS |
    //  +----+----------+----------+
    //  | 1 | 1 | 1 to 255 |
    //  +----+----------+----------+
    // (1) The VER field is set to X’05’ for this version of the protocol
    // (2) The NMETHODS field contains the number of method identifier octets
    // that appear in the METHODS field
    void get_version_and_nmethods();

    // (3) The METHODS is supported method list
    //      (3.1) X’00’ NO AUTHENTICATION REQUIRED
    //      (3.2) X’01’ GSSAPI
    //      (3.3) X’02’ USERNAME/PASSWORD
    //      (3.4) X’03’ to X’7F’ IANA ASSIGNED
    //      (3.5) X’80’ to X’FE’ RESERVED FOR PRIVATE METHODS
    //      (3.6) X’FF’ NO ACCEPTABLE METHODS
    void get_methods_list();

    SocksV5::Method choose_method();

    //  +----+--------+
    //  |VER | METHOD |
    //  +----+--------+
    //  | 1  |   1    |
    //  +----+--------+
    void reply_support_method();

    // +----+------+----------+------+----------+
    // |VER | ULEN | UNAME | PLEN | PASSWD |
    // +----+------+----------+------+----------+
    // | 1 | 1 | 1 to 255 | 1 | 1 to 255 |
    // +----+------+----------+------+----------+
    // (1) The VER field contains the current version of the subnegotiation
    // (2) The ULEN field contains the length of the UNAME field that follows
    // (3) The UNAME field contains the username as known to the source
    // operating system (4) The PLEN field contains the length of the PASSWD
    // field that follows (5) The PASSWD field contains the password association
    // with the given UNAME
    void get_username_length();

    void get_username_content();

    void get_password_length();

    void get_password_content();

    //  +----+--------+
    //  |VER | STATUS |
    //  +----+--------+
    //  | 1 | 1 |
    //  +----+--------+
    // (1) VER protocol version: X’05’
    // (2) STATUS auth result
    //      (2.1) SUCCESS X’00’
    //      (2.2) FAILURE X’01’(STATUS value other than X’00’)
    void auth_and_respond();

    //  +----+-----+-------+------+----------+----------+
    //  |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT   |
    //  +----+-----+-------+------+----------+----------+
    //  | 1  | 1   | X’00’ | 1  | Variable |     2      |
    //  +----+-----+-------+------+----------+----------+
    // (1) VER protocol version: X’05’
    // (2) CMD
    //      (2.1) CONNECT X’01’
    //      (2.2) BIND X’02’
    //      (2.3) UDP ASSOCIATE X’03’
    // (3) RSV RESERVED
    // (4) ATYP address type of following address
    //      (4.1) IP V4 address: X’01’
    //      (4.2) DOMAINNAME: X’03’
    //      (4.3) IP V6 address: X’04’
    void get_socks_request();

    // (5) DST.ADDR desired destination address
    // (6) DST.PORT desired destination port in network octet order
    void get_dst_information();

    void parse_ipv4();

    void parse_ipv6();

    void parse_domain();

    void parse_domain_length();

    void parse_domain_content(size_t read_length);

    void parse_port();

    void execute_command();

    void connect_dst_host();

    //  The UDP ASSOCIATE request is used to establish an association within
    //  the UDP relay process to handle UDP datagrams. The DST.ADDR and
    //  DST.PORT fields contain the address and port that the client expects
    //  to use to send UDP datagrams on for the association. The server MAY
    //  use this information to limit access to the association. If the
    //  client is not in possesion of the information at the time of the UDP
    //  ASSOCIATE, the client MUST use a port number and address of all
    //  zeros.
    bool check_all_zeros();

    void set_client_endpoint();

    void set_destination_endpoint();

    //  In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
    //  fields indicate the port number/address where the client MUST send
    //  UDP request messages to be relayed.
    void reply_udp_associate();

    //  +----+------+------+----------+----------+----------+
    //  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
    //  +----+------+------+----------+----------+----------+
    //  | 2 | 1 | 1 | Variable | 2 | Variable |
    //  +----+------+------+----------+----------+----------+
    // (1) RSV Reserved X’0000’
    // (2) FRAG Current fragment number
    // (3) ATYP address type of following address
    //      (3.1) IP V4 address: X’01’
    //      (3.2) DOMAINNAME: X’03’
    //      (3.3) IP V6 address: X’04’
    // (4) DST.ADDR desired destination address
    // (5) DST.PORT desired destination port
    // (6) DATA user data
    void get_udp_client();

    void receive_udp_message();

    void send_udp_to_dst();

    void send_udp_to_client();

    //  +----+-----+-------+------+----------+----------+
    //  |VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
    //  +----+-----+-------+------+----------+----------+
    //  | 1  | 1   | X’00’ | 1    | Variable |    2     |
    //  +----+-----+-------+------+----------+----------+
    // (1) VER protocol version: X’05’
    // (2) REP Reply field:
    //      (2.1) X’00’ succeeded
    //      (2.2) X’01’ general SOCKS server failure
    //      (2.3) X’02’ connection not allowed by ruleset
    //      (2.4) X’03’ Network unreachable
    //      (2.5) X’04’ Host unreachable
    //      (2.6) X’05’ Connection refused
    //      (2.7) X’06’ TTL expired
    //      (2.8) X’07’ Command not supported
    //      (2.9) X’08’ Address type not supported
    // (3) RSV RESERVED
    // (4) ATYP address type of following address
    //      (4.1) IP V4 address: X’01’
    //      (4.2) DOMAINNAME: X’03’
    //      (4.3) IP V6 address: X’04’
    // (5) BND.ADDR server bound address
    // (6) BND.PORT server bound port in network octet order
    void reply_connect_result();

    void read_from_client();

    void send_to_dst(size_t write_length);

    void read_from_dst();

    void send_to_client(size_t write_length);

protected:
    asio::io_context& ioc;
    asio::ip::tcp::resolver tcp_resolver;
    asio::ip::udp::resolver udp_resolver;
    asio::ip::tcp::socket socket;
    asio::ip::tcp::socket dst_socket;

    std::string local_host;
    uint16_t local_port;

    std::vector<uint8_t> cli_addr;
    uint16_t cli_port;
    SocksVersion ver;
    uint8_t rsv;

    /* Life Cycle Management */
    asio::steady_timer deadline;
    size_t timeout;

    /* Associate Step */
    uint8_t nmethods;
    std::vector<SocksV5::Method> methods;

    /* Auth Step*/
    uint8_t ulen;
    uint8_t plen;
    SocksV5::ReplyAuthStatus status;
    std::vector<uint8_t> uname;
    std::vector<uint8_t> passwd;

    /* Request Step */
    SocksV5::Method method;
    SocksV5::RequestCMD cmd;
    SocksV5::RequestATYP request_atyp;
    std::vector<uint8_t> dst_addr;
    uint16_t dst_port;

    /* Reply Step */
    SocksV5::ReplyATYP reply_atyp;
    SocksV5::ReplyREP rep;
    std::vector<uint8_t> bnd_addr;
    uint16_t bnd_port;

    /* Udp Associate Step */
    std::unique_ptr<asio::ip::udp::socket> udp_socket;
    uint16_t udp_rsv;
    uint8_t frag;
    asio::ip::udp::endpoint client_endpoint;
    asio::ip::udp::endpoint dst_endpoint;
    asio::ip::udp::endpoint sender_endpoint;
    size_t udp_length;

    /* Talk Step */
    std::vector<uint8_t> client_buffer;
    std::vector<uint8_t> dst_buffer;
};
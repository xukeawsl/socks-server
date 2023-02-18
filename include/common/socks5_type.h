#pragma once

namespace SocksV5 {
// clang-format off

/* SOCKSv5 Protocol Supported Methods Field */
enum class Method : uint8_t {
    NoAuth                  = 0x00,
    GSSAPI                  = 0x01,
    UserPassWd              = 0x02,
    NoAcceptable            = 0xFF,
};

/* SOCKSv5 Server Reply Autu Status */
enum class ReplyAuthStatus : uint8_t {
    Success                 = 0x00,
    Failure                 = 0xFF,
};

/* SOCKSv5 Client Request CMD Field */
enum class RequestCMD : uint8_t {
    Connect                 = 0x01,
    Bind                    = 0x02,
    UdpAssociate            = 0x03,
};

/* SOCKSv5 Client Request ATYP Field */
enum class RequestATYP : uint8_t {
    Ipv4                    = 0x01,
    DoMainName              = 0x03,
    Ipv6                    = 0x04,
};

/* SOCKSv5 Server Reply REP Field */
enum class ReplyREP : uint8_t {
    Succeeded               = 0x00,
    GenServFailed           = 0x01,
    NotAllowed              = 0x02,
    NetworkUnreachable      = 0x03,
    HostUnreachable         = 0x04,
    ConnRefused             = 0x05,
    TtlExpired              = 0x06,
    CommandNotSupported     = 0x07,
    AddrTypeNotSupported    = 0x08,
};

/* SOCKSv5 Server Reply ATYPE Field */
enum class ReplyATYP : uint8_t {
    Ipv4                    = 0x01,
    DoMainName              = 0x03,
    Ipv6                    = 0x04,
};
// clang-format on

struct MethodHash {
    size_t operator()(const Method& m) const { return static_cast<size_t>(m); }
};

struct MethodEqual {
    bool operator()(const Method& m1, const Method& m2) const noexcept {
        return static_cast<uint8_t>(m1) == static_cast<uint8_t>(m2);
    }
};

}    // namespace SocksV5

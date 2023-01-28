#pragma once

#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#include "asio.hpp"
#include "logger.h"

/* SOCKS Protocol Version Field */
enum class SocksVersion : uint8_t {
    V4 = 0x04,
    V5 = 0x05,
};

enum class ATyp : uint8_t {
    Ipv4 = 0x01,
    DoMainName = 0x03,
    Ipv6 = 0x04,
};

class noncopyable {
protected:
    noncopyable() {}
    ~noncopyable() {}
    noncopyable(const noncopyable&) = delete;
    const noncopyable& operator=(const noncopyable&) = delete;
};

namespace convert {

template <typename InternetProtocol>
std::string format_address(
    const asio::ip::basic_endpoint<InternetProtocol>& endpoint) {
    if (endpoint.address().is_v6()) {
        return "[" + endpoint.address().to_string() + "]" + ":" +
               std::to_string(endpoint.port());
    }
    return endpoint.address().to_string() + ":" +
           std::to_string(endpoint.port());
}

std::string dst_to_string(const std::vector<uint8_t>& dst_addr, ATyp addr_type);

}    // namespace convert
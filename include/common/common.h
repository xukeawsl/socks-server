#pragma once

#include <iostream>
#include <cstring>
#include <vector>
#include <memory>
#include <thread>

#include "asio.hpp"
#include "common/logger.h"

/* SOCKS Protocol Version Field */
enum class SocksVersion : uint8_t {
    V4 = 0x04,
    V5 = 0x05
};

class noncopyable {
protected:
    noncopyable() {}
    ~noncopyable() {}
    noncopyable(const noncopyable&) = delete;
    const noncopyable& operator = (const noncopyable&) = delete;
};


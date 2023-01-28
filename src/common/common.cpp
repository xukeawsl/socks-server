#include "common/common.h"

namespace convert {

std::string dst_to_string(const std::vector<uint8_t>& dst_addr,
                          ATyp addr_type) {
    static char addr[UINT8_MAX];
    std::memset(addr, 0, sizeof(addr));

    switch (addr_type) {
        case ATyp::Ipv4: {
            std::snprintf(addr, sizeof(addr), "%d.%d.%d.%d", dst_addr[0],
                          dst_addr[1], dst_addr[2], dst_addr[3]);
        } break;

        case ATyp::Ipv6: {
            std::snprintf(addr, sizeof(addr),
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"
                          "02x:%02x%02x:%"
                          "02x%02x",
                          dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3],
                          dst_addr[4], dst_addr[5], dst_addr[6], dst_addr[7],
                          dst_addr[8], dst_addr[9], dst_addr[10], dst_addr[11],
                          dst_addr[12], dst_addr[13], dst_addr[14],
                          dst_addr[15]);
        } break;

        case ATyp::DoMainName: {
            std::memcpy(addr, dst_addr.data(), dst_addr.size());
        } break;
    }

    return std::string(addr);
}

}    // namespace convert
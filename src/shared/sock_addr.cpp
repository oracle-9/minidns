#include "shared/sock_addr.hpp"

#include <algorithm>
#include <charconv>
#include <iterator>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace minidns {

// * NOTE: Address is in network byte order, port is in host byte order.
static std::pair<in_addr_t, in_port_t>
parse_addr_and_port(std::string_view str, in_port_t default_port);

HostSockAddr HostSockAddr::from_native(sockaddr_in const native) noexcept {
    return HostSockAddr {
        .addr = native.sin_addr.s_addr,
        .port = native.sin_port,
    };
}

HostSockAddr HostSockAddr::from_str(
    std::string_view const str,
    in_port_t const default_port
) {
    auto const [addr_no, port_ho] = parse_addr_and_port(str, default_port);
    return HostSockAddr {
        .addr = ntohl(addr_no),
        .port = port_ho,
    };
}

NetSockAddr HostSockAddr::net_order() const noexcept {
    return NetSockAddr {
        .addr = htonl(this->addr),
        .port = htons(this->port),
    };
}

sockaddr_in HostSockAddr::native() const noexcept {
    auto r = sockaddr_in {};
    r.sin_family = AF_INET;
    r.sin_addr = {this->addr};
    r.sin_port = this->port;
    return r;
}

bool operator==(HostSockAddr const lhs, HostSockAddr const rhs) noexcept {
    return lhs.addr == rhs.addr and lhs.port == rhs.port;
}

NetSockAddr NetSockAddr::from_native(sockaddr_in const native) noexcept {
    return NetSockAddr {
        .addr = native.sin_addr.s_addr,
        .port = native.sin_port,
    };
}

NetSockAddr NetSockAddr::from_str(
    std::string_view const str,
    in_port_t const default_port
) {
    auto const [addr_no, port_ho] = parse_addr_and_port(str, default_port);
    return {
        .addr = addr_no,
        .port = htons(port_ho),
    };
}

HostSockAddr NetSockAddr::host_order() const noexcept {
    return {
        .addr = ntohl(this->addr),
        .port = ntohs(this->port),
    };
}

sockaddr_in NetSockAddr::native() const noexcept {
    sockaddr_in r;
    r.sin_family = AF_INET;
    r.sin_addr = {this->addr};
    r.sin_port = this->port;
    return r;
}

bool operator==(NetSockAddr const lhs, NetSockAddr const rhs) noexcept {
    return lhs.addr == rhs.addr and lhs.port == rhs.port;
}

static std::pair<in_addr_t, in_port_t>
parse_addr_and_port(std::string_view const str, in_port_t const default_port) {
    std::size_t ipv4_addr_len;
    std::size_t const colon_pos = str.find(':');
    in_port_t port;
    if (colon_pos != std::string_view::npos) {
        ipv4_addr_len = colon_pos;
        std::string_view const port_str = str.substr(colon_pos + 1);
        char const* const port_begin = port_str.data();
        char const* const port_end = port_str.data() + port_str.size();
        auto const [end, err] = std::from_chars(port_begin, port_end, port);
        if (err != std::errc() or end != port_end) {
            throw std::invalid_argument(
                fmt::format("invalid server port '{}'", port_str)
            );
        }
    } else {
        ipv4_addr_len = str.length();
        port = default_port;
    }

    in_addr addr;
    char buf[INET_ADDRSTRLEN];
    char* const end = std::copy_n(
        str.data(),
        std::min(ipv4_addr_len, std::size(buf) - 1),
        buf
    );
    *end = '\0';
    errno = 0;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        std::string err_msg
            = fmt::format("invalid IPv4 address '{:.{}}'", buf, end - buf);
        if (errno != 0) {
            fmt::format_to(
                std::back_inserter(err_msg),
                ": {}",
                strerror_mt(errno)
            );
        }
        throw std::invalid_argument(std::move(err_msg));
    }

    return {addr.s_addr, port};
}

} // namespace minidns

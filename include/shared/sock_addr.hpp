#pragma once

#include "shared/config.hpp"
#include "shared/util/strerror_mt.hpp"

#include <cerrno>
#include <fmt/format.h>
#include <string_view>

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
}

namespace minidns {

struct HostSockAddr;
struct NetSockAddr;

struct HostSockAddr final {
    in_addr_t addr;
    in_port_t port;

    static HostSockAddr from_native(sockaddr_in native) noexcept;

    static HostSockAddr
    from_str(std::string_view str, in_port_t default_port = DEFAULT_PORT);

    NetSockAddr net_order() const noexcept;

    sockaddr_in native() const noexcept;
};

bool operator==(HostSockAddr lhs, HostSockAddr rhs) noexcept;

struct NetSockAddr final {
    in_addr_t addr;
    in_port_t port;

    static NetSockAddr from_native(sockaddr_in native) noexcept;

    static NetSockAddr
    from_str(std::string_view str, in_port_t default_port = DEFAULT_PORT);

    HostSockAddr host_order() const noexcept;

    sockaddr_in native() const noexcept;
};

bool operator==(NetSockAddr lhs, NetSockAddr rhs) noexcept;

} // namespace minidns

template <>
struct fmt::formatter<minidns::HostSockAddr> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::HostSockAddr const sock_addr, FormatContext& ctx)
        -> decltype(ctx.out()) {
        char buf[INET_ADDRSTRLEN];
        auto const addr_no = in_addr {htonl(sock_addr.addr)};
        char const* const addr_str
            = inet_ntop(AF_INET, &addr_no, buf, std::size(buf));
        if (addr_str == nullptr) {
            throw fmt::format_error(fmt::format(
                "failed to convert IPv4 address to string: {}",
                strerror_mt(errno)
            ));
        }
        return format_to(ctx.out(), "{}:{}", addr_str, sock_addr.port);
    }
};

template <>
struct fmt::formatter<minidns::NetSockAddr> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::NetSockAddr const sock_addr, FormatContext& ctx)
        -> decltype(ctx.out()) {
        char buf[INET_ADDRSTRLEN];
        auto const addr_no = in_addr {sock_addr.addr};
        char const* const addr_str
            = inet_ntop(AF_INET, &addr_no, buf, std::size(buf));
        if (addr_str == nullptr) {
            throw fmt::format_error(fmt::format(
                "failed to convert IPv4 address to string: {}",
                strerror_mt(errno)
            ));
        }
        return format_to(ctx.out(), "{}:{}", addr_str, ntohs(sock_addr.port));
    }
};

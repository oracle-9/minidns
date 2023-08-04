#pragma once

#include "shared/sock_addr.hpp"

#include <concepts>
#include <cstdint>
#include <fmt/format.h>
#include <optional>
#include <string>

namespace minidns {

struct NS final {
    std::string domain; // [1, 256) chars
    std::string name;   // [1, 256) chars
    std::int32_t ttl;
    std::optional<std::uint8_t> priority;
};

struct MX final {
    std::string domain; // [1, 256) chars
    std::string name;   // [1, 256) chars
    std::int32_t ttl;
    std::optional<uint8_t> priority;
};

struct A final {
    std::string domain; // [1, 256) chars
    HostSockAddr sock_addr;
    std::int32_t ttl;
    std::optional<std::uint8_t> priority;
};

struct PTR final {
    HostSockAddr sock_addr;
    std::string domain; // [1, 256) chars
    std::int32_t ttl;
};

template <typename T>
concept DNSRecord = std::same_as<T, NS> or std::same_as<T, MX>
                 or std::same_as<T, A> or std::same_as<T, PTR>;

} // namespace minidns

template <>
struct fmt::formatter<minidns::NS> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::NS const& ns, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        format_to(ctx.out(), "{} {} {}", ns.domain, ns.name, ns.ttl);
        if (ns.priority.has_value()) {
            format_to(ctx.out(), " {}", *ns.priority);
        }
        return ctx.out();
    }
};

template <>
struct fmt::formatter<minidns::MX> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::MX const& mx, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        format_to(ctx.out(), "{} {} {}", mx.domain, mx.name, mx.ttl);
        if (mx.priority.has_value()) {
            format_to(ctx.out(), " {}", *mx.priority);
        }
        return ctx.out();
    }
};

template <>
struct fmt::formatter<minidns::A> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::A const& a, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        format_to(ctx.out(), "{} {} {}", a.domain, a.sock_addr, a.ttl);
        if (a.priority.has_value()) {
            format_to(ctx.out(), " {}", *a.priority);
        }
        return ctx.out();
    }
};

template <>
struct fmt::formatter<minidns::PTR> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::PTR const& ptr, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        return format_to(
            ctx.out(),
            "{} {} {}",
            ptr.sock_addr,
            ptr.domain,
            ptr.ttl
        );
    }
};

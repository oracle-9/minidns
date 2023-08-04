#pragma once

#include "shared/dns_record.hpp"
#include "shared/util/to_underlying.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace minidns {

class Query final {
  public:
    // 0bQRA
    // Q = 0: query response, Q = 1: query.
    // R = 0: iterative, R = 1: recursive.
    // A = (bool) authoritative.
    enum Flags : std::uint8_t {
        QUERY = 0b001, // Is this is a query?

        RECURSIVE = 0b010, // Use recursion?

        AUTHORITATIVE = 0b100, // Is this an authoritative response?
    };

    enum class ResponseCode : std::uint8_t {
        SUCCESS, // No errors.

        NO_SUCH_TYPE, // Domain exists, but could not provide
                      // a response concerning the specified
                      // query type.

        NO_SUCH_DOMAIN, // Domain doesn't exist.

        DECODE_ERR, // Error decoding a query.
    };

    enum class Type : std::uint8_t {
        NONE, // Zero value, because it's useful.
        NS,   // Name server.
        MX,   // Mail exchange.
        A,    // IPv4 address.
    };

    using ResponseValues
        = std::variant<std::vector<NS>, std::vector<MX>, std::vector<A>>;

    class EncodeError final : public std::exception {
      private:
        std::string msg;

      public:
        template <typename... Args>
        EncodeError(fmt::format_string<Args...> fmt_str, Args&&... args)
          : msg(fmt::format(fmt_str, std::forward<Args>(args)...)) {}

        char const* what() const noexcept override;
    };

    struct DecodeState final {
        std::size_t byte_idx;
        std::span<std::uint8_t const> encoded_bytes;
        std::span<std::string_view const> successfully_decoded_fields;
    };

    class DecodeError final : public std::exception {
      private:
        std::string msg;

      public:
        template <typename... Args>
        DecodeError(
            DecodeState const& state,
            fmt::format_string<Args...> fmt_str,
            Args&&... args
        )
          : msg(fmt::format(fmt_str, std::forward<Args>(args)...)) {
            std::size_t const num_encoded_bytes = state.encoded_bytes.size();
            if (num_encoded_bytes == 0) {
                this->msg += "; encoded bytes: <empty>";
            } else {
                fmt::format_to(
                    std::back_inserter(this->msg),
                    "; successfully decoded fields: [{}]"
                    "; byte index: {}"
                    "; encoded bytes ({}): {:02x} >>>{:02x}<<< {:02x}",
                    fmt::join(state.successfully_decoded_fields, ", "),
                    state.byte_idx,
                    num_encoded_bytes,
                    fmt::join(state.encoded_bytes.first(state.byte_idx), " "),
                    state.encoded_bytes[state.byte_idx],
                    fmt::join(
                        state.encoded_bytes.subspan(state.byte_idx + 1),
                        " "
                    )
                );
            }
        }

        char const* what() const noexcept override;
    };

    static constexpr std::string_view TYPE_NAMES[] = {"EMPTY", "NS", "MX", "A"};

    // Fields organized by alignment to minimize padding.
    ResponseValues vals;   // [0, 256) elements.
    std::vector<NS> auths; // [0, 256) elements.
    std::vector<A> extras; // [0, 256) elements.
    std::string domain;    // [0, 256) chars.
    std::uint16_t id;      // [1, 65536)
    // Flags, response code and type are packed into a single byte.
    Flags flags     : 3; // bitwise or of Flags.
    ResponseCode rc : 2;
    Type type       : 2;

    static Query from_client(std::string&& domain, Type type, Flags flags);

    static bool valid_id(std::uint16_t id) noexcept;

    static bool valid_flags(std::underlying_type_t<Flags> flags) noexcept;

    static bool valid_response_code(std::underlying_type_t<ResponseCode> rc
    ) noexcept;

    static bool valid_type(std::underlying_type_t<Type> type) noexcept;

    static std::uint16_t next_id(std::uint16_t id) noexcept;

    static std::uint16_t random_id();

    static bool str_to_type(std::string_view type_name, Type& out) noexcept;

    std::size_t encode_to(std::span<std::uint8_t> buf) const;

    std::size_t decode_from(std::span<std::uint8_t const> buf);
};

Query::Flags operator~(Query::Flags lhs) noexcept;
Query::Flags operator&(Query::Flags lhs, Query::Flags rhs) noexcept;
Query::Flags operator|(Query::Flags lhs, Query::Flags rhs) noexcept;
Query::Flags operator^(Query::Flags lhs, Query::Flags rhs) noexcept;
Query::Flags& operator&=(Query::Flags& lhs, Query::Flags rhs) noexcept;
Query::Flags& operator|=(Query::Flags& lhs, Query::Flags rhs) noexcept;
Query::Flags& operator^=(Query::Flags& lhs, Query::Flags rhs) noexcept;

} // namespace minidns

template <>
struct fmt::formatter<minidns::Query::Flags> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::Query::Flags const flags, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        using enum minidns::Query::Flags;
        bool first_flag = true;
        char buf[sizeof("Q+R+A") - 1]; // don't need null terminator.
        char* buf_iter = buf;
        if (flags & QUERY) {
            *buf_iter++ = 'Q';
            first_flag = false;
        }
        if (flags & RECURSIVE) {
            if (not first_flag) {
                *buf_iter++ = '+';
                first_flag = false;
            }
            *buf_iter++ = 'R';
        }
        if (flags & AUTHORITATIVE) {
            if (not first_flag) {
                *buf_iter++ = '+';
            }
            *buf_iter++ = 'A';
        }
        return format_to(ctx.out(), "{}", std::string_view(buf, buf_iter));
    }
};

template <>
struct fmt::formatter<minidns::Query::Type> {
    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(minidns::Query::Type const type, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        return format_to(
            ctx.out(),
            "{}",
            minidns::Query::TYPE_NAMES[static_cast<std::size_t>(type)]
        );
    }
};

template <>
struct fmt::formatter<minidns::Query> {
    bool verbose = false;

    constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
        auto it = ctx.begin();
        auto const end = ctx.end();
        if (it != end && (*it == 'v')) {
            this->verbose = true;
            ++it;
        }
        if (it != end && *it != '}') {
            throw format_error("invalid format");
        }
        return it;
    }

    template <typename FormatContext>
    auto format(minidns::Query const& query, FormatContext& ctx) const
        -> decltype(ctx.out()) {
        if (this->verbose) {
            format_to(
                ctx.out(),
                "MESSAGE-ID = {}, FLAGS = {}, RESPONSE-CODE = {}, "
                "N-VALUES = {}, N-AUTHORITIES = {}, N-EXTRA-VALUES = {},; "
                "QUERY-INFO.NAME = {:.{}}, QUERY-INFO.TYPE = {},;",
                query.id,
                query.flags,
                to_underlying(query.rc),
                std::visit([](auto& vals) { return vals.size(); }, query.vals),
                query.auths.size(),
                query.extras.size(),
                query.domain,
                query.domain.length(),
                query.type
            );
            std::visit(
                [&ctx](auto& vals) {
                    for (auto& val : vals) {
                        format_to(ctx.out(), "\nRESPONSE-VALUES = {},", val);
                    }
                    format_to(ctx.out(), ";");
                },
                query.vals
            );
            for (minidns::NS const& auth : query.auths) {
                format_to(ctx.out(), "\nAUTHORITIES-VALUES = {},", auth);
            }
            format_to(ctx.out(), ";");
            for (minidns::A const& extra : query.extras) {
                format_to(ctx.out(), "\nEXTRA-VALUES = {},", extra);
            }
            format_to(ctx.out(), ";");
        } else {
            using namespace fmt::literals;
            format_to(
                ctx.out(),
                "{id},{flags},{response_code},"
                "{num_values},{num_authorities},{num_extra_values};"
                "{domain:.{domain_len}},{type};",
                "id"_a = query.id,
                "flags"_a = query.flags,
                "response_code"_a = to_underlying(query.rc),
                "num_values"_a = std::visit(
                    [](auto& vals) { return vals.size(); },
                    query.vals
                ),
                "num_authorities"_a = query.auths.size(),
                "num_extra_values"_a = query.extras.size(),
                "domain"_a = query.domain,
                "domain_len"_a = query.domain.length(),
                "type"_a = query.type
            );
            std::visit(
                [&ctx](auto& vals) {
                    format_to(ctx.out(), "{};", join(vals, ","));
                },
                query.vals
            );
            format_to(
                ctx.out(),
                "{};{};",
                join(query.auths, ","),
                join(query.extras, ",")
            );
        }
        return ctx.out();
    }
};

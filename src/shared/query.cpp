// endian.h is not available on all platforms, so we need to define this macro.
#ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

#include "shared/query.hpp"

#include "shared/config.hpp"

#include <algorithm>
#include <climits>
#include <concepts>
#include <random>
#include <stdexcept>

extern "C" {
#include <arpa/inet.h>
#include <endian.h>
}

static_assert(CHAR_BIT == 8, "architecture not supported");

namespace minidns {

// clang-format off
static constexpr std::size_t ENCODED_HEADER_SIZE
    = sizeof(Query::id)
    + 1 // flags + response_code take 1 byte in total.
    + sizeof(std::uint8_t) * 3; // num_vals, num_auths, num_extra_vals
// clang-format on

// In order of decoding.
static constexpr std::string_view FIELD_NAMES_STORE[] = {
    "id",
    "flags",
    "response code",
    "type",
    "number of values",
    "number of authorities",
    "number of extra values",
    "domain length",
    "domain",
    "response values",
    "authorities values",
    "extra values",
};

// std::span has a nicer interface than a raw array, but it doesn't own the
// underlying data, so we need to store it separately. In this case, in
// FIELD_NAMES_STORE.
static constexpr std::span FIELD_NAMES = FIELD_NAMES_STORE;

static auto seed_provider = std::random_device();
static auto rand_generator = std::default_random_engine(seed_provider());
static auto id_rand_distribution
    = std::uniform_int_distribution<std::uint16_t>(1, 65535);

template <typename T>
static std::uint8_t b(T val) noexcept;

template <typename T>
static void write_bytes(
    T const* src,
    std::uint8_t* dest,
    std::size_t size = sizeof(T)
) noexcept;

template <typename T>
static T& read_bytes(
    T* dest,
    std::uint8_t const* src,
    std::size_t size = sizeof(T)
) noexcept;

template <DNSRecord Record>
static void encode_record(
    Record const& record,
    std::uint8_t*& out,
    std::size_t& num_remaining_bytes
);

template <DNSRecord Record>
static Record decode_record(
    Query::DecodeState& state,
    std::uint8_t const*& in,
    std::size_t& num_remaining_bytes
);

char const* Query::EncodeError::what() const noexcept {
    return msg.c_str();
}

char const* Query::DecodeError::what() const noexcept {
    return msg.c_str();
}

Query Query::from_client(
    std::string&& domain,
    Type const type,
    Flags const flags
) {
    if (type == Type::NONE) {
        throw std::invalid_argument("type cannot be NONE");
    }
    std::size_t const domain_len = domain.length();
    if (domain_len > MAX_DOMAIN_LEN) {
        throw std::invalid_argument(fmt::format(
            "domain too long; maximum length: {}; actual length: {}",
            MAX_DOMAIN_LEN,
            domain_len
        ));
    }
    return Query {
        .vals = {},
        .auths = {},
        .extras = {},
        .domain = std::move(domain),
        .id = random_id(),
        .flags = flags,
        .rc = ResponseCode::SUCCESS,
        .type = type,
    };
}

bool Query::valid_id(std::uint16_t const id) noexcept {
    return id != 0;
}

bool Query::valid_flags(std::underlying_type_t<Flags> const flags) noexcept {
    return flags < 0b1000;
}

bool Query::valid_response_code(std::underlying_type_t<ResponseCode> const rc
) noexcept {
    return rc < 4;
}

bool Query::valid_type(std::underlying_type_t<Type> const type) noexcept {
    return type < 4;
}

std::uint16_t Query::next_id(std::uint16_t const id) noexcept {
    return (id % 65535) + 1;
}

std::uint16_t Query::random_id() {
    return id_rand_distribution(rand_generator);
}

bool Query::str_to_type(std::string_view const type_name, Type& out) noexcept {
    auto const match = std::ranges::find(TYPE_NAMES, type_name);
    if (match == std::end(TYPE_NAMES)) {
        return false;
    }
    out = static_cast<Type>(match - std::begin(TYPE_NAMES));
    return true;
}

std::size_t Query::encode_to(std::span<std::uint8_t> const buf) const {
    std::uint8_t* out = buf.data();
    std::size_t num_remaining_bytes = buf.size();

    if (ENCODED_HEADER_SIZE > num_remaining_bytes) {
        throw EncodeError(
            "insufficient memory to encode header; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            ENCODED_HEADER_SIZE,
            num_remaining_bytes
        );
    }

    // First encode the the query id, in network order.
    std::uint16_t const id_no = htobe16(this->id);
    write_bytes(&id_no, out);
    out += sizeof(this->id);

    // Then encode the query type, response code and flags, in the following bit
    // format:
    // [_, t, t, rc, rc, f, f, f]
    // Technically, the type should be stored in the payload, but if we store
    // it in the header instead, we can avoid the extra bytes and save some
    // bandwidth.
    std::uint8_t type_rc_flags = b(this->type);
    type_rc_flags <<= 2;
    type_rc_flags |= b(this->rc);
    type_rc_flags <<= 3;
    type_rc_flags |= b(this->flags);
    *out++ = type_rc_flags;

    // Then encode the number of values, authorities and extra values.
    // Since each of these fields is only 1 byte, we can just copy them directly
    // without worrying about endianness.
    *out++ = std::visit([](auto& vals) { return b(vals.size()); }, this->vals);
    *out++ = b(this->auths.size());
    *out++ = b(this->extras.size());

    // The header is now complete, so we can move on to the payload.
    num_remaining_bytes -= ENCODED_HEADER_SIZE;

    // Encode the domain length.
    std::size_t const domain_len = this->domain.length();
    std::size_t const sizeof_domain_len_and_domain
        = sizeof(std::uint8_t) + domain_len;
    if (sizeof_domain_len_and_domain > num_remaining_bytes) {
        throw EncodeError(
            "insufficient memory to encode domain; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            sizeof_domain_len_and_domain,
            num_remaining_bytes
        );
    }
    *out++ = b(domain_len);

    // Encode the domain itself, in raw bytes.
    write_bytes(this->domain.data(), out, domain_len);
    out += domain_len;
    num_remaining_bytes -= sizeof_domain_len_and_domain;

    // Next, encode the response values.
    std::visit(
        [&out, &num_remaining_bytes](auto& vals) {
            for (auto& record : vals) {
                encode_record(record, out, num_remaining_bytes);
            }
        },
        this->vals
    );

    // Next, encode the authorities, i.e. the nameservers managing the domain.
    for (NS const& record : this->auths) {
        encode_record(record, out, num_remaining_bytes);
    }

    // Finally, encode the extra values, i.e. the additional A records.
    for (A const& record : this->extras) {
        encode_record(record, out, num_remaining_bytes);
    }

    // Return the number of bytes written.
    return buf.size() - num_remaining_bytes;
}

std::size_t Query::decode_from(std::span<std::uint8_t const> const buf) {
    std::uint8_t const* in = buf.data();
    std::size_t num_remaining_bytes = buf.size();

    DecodeState decode_state = {
        .byte_idx = 0,
        .encoded_bytes = buf,
        .successfully_decoded_fields = {},
    };

    if (ENCODED_HEADER_SIZE > num_remaining_bytes) {
        throw DecodeError(
            decode_state,
            "insufficient memory to decode header; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            ENCODED_HEADER_SIZE,
            num_remaining_bytes
        );
    }

    // First decode the query id, in network order to host order.
    std::uint16_t id;
    id = be16toh(read_bytes(&id, in));
    if (not valid_id(id)) {
        throw DecodeError(
            decode_state,
            "invalid id {}, must be in range [1, 65536)",
            this->id
        );
    }
    this->id = id;
    in += sizeof(this->id);
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(1);
    decode_state.byte_idx += sizeof(this->id);

    // Then decode the query flags, response code and type, in the following bit
    // format:
    // [_, t, t, rc, rc, f, f, f]
    // Technically, the type should be stored in the payload, but if we store
    // it in the header instead, we can avoid the extra bytes and save some
    // bandwidth.
    std::uint8_t type_rc_flags = *in++;
    std::uint8_t const flags = type_rc_flags & 0b111;
    if (not valid_flags(flags)) {
        throw DecodeError(
            decode_state,
            "invalid flags {:#b}, must be in range [0, 0b1000)",
            flags
        );
    }
    this->flags = static_cast<Flags>(flags);
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(2);

    type_rc_flags >>= 3;
    std::uint8_t const rc = type_rc_flags & 0b11;
    if (not valid_response_code(rc)) {
        throw DecodeError(
            decode_state,
            "invalid response code {}, must be in range [0, 4)",
            rc
        );
    }
    this->rc = static_cast<ResponseCode>(rc);
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(3);

    type_rc_flags >>= 2;
    std::uint8_t const type = type_rc_flags & 0b11;
    if (not valid_type(type)) {
        throw DecodeError(
            decode_state,
            "invalid type {}, must be in range [0, 4)",
            type
        );
    }
    this->type = static_cast<Type>(type);
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(4);
    ++decode_state.byte_idx;

    // Then decode the number of values, authorities and extra values.
    // Since each of these fields is only 1 byte, we can just copy them directly
    // without worrying about endianness.
    std::size_t const num_vals = *in++;
    std::size_t const num_auths = *in++;
    std::size_t const num_extra_vals = *in++;
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(7);
    decode_state.byte_idx += sizeof(std::uint8_t) * 3;

    // The header is now complete, so we can move on to the payload.
    num_remaining_bytes -= ENCODED_HEADER_SIZE;

    // Decode the domain length.
    if (sizeof(std::uint8_t) > num_remaining_bytes) {
        throw DecodeError(
            decode_state,
            "insufficient memory to decode domain length; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            sizeof(std::uint8_t),
            num_remaining_bytes
        );
    }
    std::uint8_t const domain_len = b(*in++);
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(8);
    decode_state.byte_idx += sizeof(domain_len);
    num_remaining_bytes -= sizeof(domain_len);

    // Decode the domain itself, in raw bytes.
    if (domain_len > num_remaining_bytes) {
        throw DecodeError(
            decode_state,
            "insufficient memory to decode domain; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            domain_len,
            num_remaining_bytes
        );
    }
    // Casting uint8_t* to char* is safe because we already asserted that
    // CHAR_BIT == 8.
    this->domain
        = std::string_view(reinterpret_cast<char const*>(in), domain_len);
    in += domain_len;
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(9);
    decode_state.byte_idx += domain_len;
    num_remaining_bytes -= domain_len;

    // Next, decode the response values.
    std::visit(
        [&in, &decode_state, &num_remaining_bytes, num_vals]<DNSRecord Record>(
            std::vector<Record>& vals
        ) {
            vals.clear();
            vals.reserve(num_vals);
            for (std::size_t i = 0; i < num_vals; ++i) {
                vals.push_back(
                    decode_record<Record>(decode_state, in, num_remaining_bytes)
                );
            }
        },
        this->vals
    );
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(10);

    // Next, decode the authorities, i.e. the nameservers managing the domain.
    this->auths.clear();
    this->auths.reserve(num_auths);
    for (std::size_t i = 0; i < num_auths; ++i) {
        this->auths.push_back(
            decode_record<NS>(decode_state, in, num_remaining_bytes)
        );
    }
    decode_state.successfully_decoded_fields = FIELD_NAMES.first(11);

    // Finally, decode the extra values, i.e. the additional A records.
    this->extras.clear();
    this->extras.reserve(num_extra_vals);
    for (std::size_t i = 0; i < num_extra_vals; ++i) {
        this->extras.push_back(
            decode_record<A>(decode_state, in, num_remaining_bytes)
        );
    }
    decode_state.successfully_decoded_fields = FIELD_NAMES;

    // Return the number of bytes read.
    return decode_state.byte_idx;
}

Query::Flags operator~(Query::Flags const lhs) noexcept {
    return static_cast<Query::Flags>(~to_underlying(lhs));
}

Query::Flags
operator&(Query::Flags const lhs, Query::Flags const rhs) noexcept {
    return static_cast<Query::Flags>(to_underlying(lhs) & to_underlying(rhs));
}

Query::Flags
operator|(Query::Flags const lhs, Query::Flags const rhs) noexcept {
    return static_cast<Query::Flags>(to_underlying(lhs) | to_underlying(rhs));
}

Query::Flags
operator^(Query::Flags const lhs, Query::Flags const rhs) noexcept {
    return static_cast<Query::Flags>(to_underlying(lhs) ^ to_underlying(rhs));
}

Query::Flags& operator&=(Query::Flags& lhs, Query::Flags const rhs) noexcept {
    lhs = lhs & rhs;
    return lhs;
}

Query::Flags& operator|=(Query::Flags& lhs, Query::Flags const rhs) noexcept {
    lhs = lhs | rhs;
    return lhs;
}

Query::Flags& operator^=(Query::Flags& lhs, Query::Flags const rhs) noexcept {
    lhs = lhs ^ rhs;
    return lhs;
}

template <typename T>
static std::uint8_t b(T const val) noexcept {
    return static_cast<std::uint8_t>(val);
}

template <typename T>
static void write_bytes(
    T const* const src,
    std::uint8_t* const dest,
    std::size_t const size
) noexcept {
    std::copy_n(reinterpret_cast<std::uint8_t const*>(src), size, dest);
}

template <typename T>
static T& read_bytes(
    T* const dest,
    std::uint8_t const* const src,
    std::size_t const size
) noexcept {
    std::copy_n(src, size, reinterpret_cast<std::uint8_t*>(dest));
    return *dest;
}

template <DNSRecord Record>
    requires std::same_as<Record, NS> || std::same_as<Record, MX>
static void encode_ns_or_mx(
    Record const& record,
    std::uint8_t*& out,
    std::size_t& num_remaining_bytes
) {
    bool const has_priority = record.priority.has_value();

    std::size_t const record_size
        = sizeof(record.ttl)     // The TTL.
        + sizeof(std::uint8_t)   // Whether or not the record has a priority.
        + sizeof(std::uint8_t)   // The length of the domain.
        + sizeof(std::uint8_t)   // The length of the nameserver.
        + record.domain.length() // The domain itself.
        + record.name.length()   // The nameserver itself.
        + (has_priority ? sizeof(*record.priority) : 0
        ); // The priority, if it exists.

    if (record_size > num_remaining_bytes) {
        if constexpr (std::same_as<Record, NS>) {
            throw Query::EncodeError(
                "insufficient memory to encode NS record; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                record_size,
                num_remaining_bytes
            );
        } else if constexpr (std::same_as<Record, MX>) {
            throw Query::EncodeError(
                "insufficient memory to encode MX record; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                record_size,
                num_remaining_bytes
            );
        }
    }

    // Encode the TTL, in network order.
    auto const ttl = htobe32(static_cast<std::uint32_t>(record.ttl));
    write_bytes(&ttl, out);
    out += sizeof(ttl);

    // Encode a byte representing whether or not the record has a priority.
    *out++ = b(has_priority);

    // Encode the domain length.
    *out++ = b(record.domain.length());

    // Encode the nameserver length.
    *out++ = b(record.name.length());

    // Encode the domain itself.
    write_bytes(record.domain.data(), out, record.domain.length());
    out += record.domain.length();

    // Encode the nameserver itself.
    write_bytes(record.name.data(), out, record.name.length());
    out += record.name.length();

    // Encode the priority, if it exists.
    if (has_priority) {
        *out++ = b(*record.priority);
    }

    num_remaining_bytes -= record_size;
}

static void
encode_a(A const& a, std::uint8_t*& out, std::size_t& num_remaining_bytes) {
    bool const has_priority = a.priority.has_value();

    std::size_t const record_size
        = sizeof(a.sock_addr.addr) // The IPv4 address.
        + sizeof(a.sock_addr.port) // The port.
        + sizeof(a.ttl)            // The TTL.
        + sizeof(std::uint8_t)     // Whether or not the record has a priority.
        + sizeof(std::uint8_t)     // The length of the domain.
        + a.domain.length()        // The domain itself.
        + (has_priority ? sizeof(*a.priority) : 0
        ); // The priority, if it exists.

    if (record_size > num_remaining_bytes) {
        throw Query::EncodeError(
            "insufficient memory to encode A record; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            record_size,
            num_remaining_bytes
        );
    }

    // Encode the IPv4 socket address, in network order.
    NetSockAddr const sock_addr_no = a.sock_addr.net_order();
    write_bytes(&sock_addr_no.addr, out);
    out += sizeof(sock_addr_no.addr);
    write_bytes(&sock_addr_no.port, out);
    out += sizeof(sock_addr_no.port);

    // Encode the TTL, in network order.
    std::uint32_t const ttl_no = htobe32(static_cast<std::uint32_t>(a.ttl));
    write_bytes(&ttl_no, out);
    out += sizeof(ttl_no);

    // Encode a byte representing whether or not the record has a priority.
    *out++ = b(has_priority);

    // Encode the domain length.
    std::size_t const domain_len = a.domain.length();
    *out++ = b(domain_len);

    // Encode the domain itself.
    write_bytes(a.domain.data(), out, domain_len);
    out += domain_len;

    // Encode the priority.
    if (has_priority) {
        *out++ = *a.priority;
    }

    num_remaining_bytes -= record_size;
}

template <DNSRecord Record>
static void encode_record(
    Record const& record,
    std::uint8_t*& out,
    std::size_t& num_remaining_bytes
) {
    if constexpr (std::same_as<Record, NS> or std::same_as<Record, MX>) {
        encode_ns_or_mx(record, out, num_remaining_bytes);
    } else if constexpr (std::same_as<Record, A>) {
        encode_a(record, out, num_remaining_bytes);
    }
}

template <DNSRecord Record>
    requires std::same_as<Record, NS> || std::same_as<Record, MX>
static Record decode_ns_or_mx(
    Query::DecodeState& state,
    std::uint8_t const*& in,
    std::size_t& num_remaining_bytes
) {
    // Does not include the domain, nameserver and priority, since those are
    // variable-length and cannot be determined beforehand.
    std::size_t const record_size
        = sizeof(A::ttl)        // The TTL.
        + sizeof(std::uint8_t)  // Whether or not the record has a priority.
        + sizeof(std::uint8_t)  // The length of the domain.
        + sizeof(std::uint8_t); // The length of the nameserver.

    if (record_size > num_remaining_bytes) {
        if constexpr (std::same_as<Record, NS>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode NS record; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                record_size,
                num_remaining_bytes
            );
        } else if constexpr (std::same_as<Record, MX>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode MX record; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                record_size,
                num_remaining_bytes
            );
        }
    }

    // Decode the TTL, in network order.
    std::uint32_t ttl_no;
    read_bytes(&ttl_no, in);
    in += sizeof(ttl_no);

    // Decode a byte representing whether or not the record has a priority.
    bool const has_priority = *in++;

    // Decode the domain length.
    std::uint8_t const domain_len = *in++;

    // Decode the nameserver length.
    std::uint8_t const nameserver_len = *in++;

    num_remaining_bytes -= record_size;
    state.byte_idx += record_size;

    // Decode the domain itself.
    if (domain_len > num_remaining_bytes) {
        if constexpr (std::same_as<Record, NS>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode NS record domain; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                domain_len,
                num_remaining_bytes
            );
        } else if constexpr (std::same_as<Record, MX>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode MX record domain; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                domain_len,
                num_remaining_bytes
            );
        }
    }
    auto domain = std::string(reinterpret_cast<char const*>(in), domain_len);
    in += domain_len;
    num_remaining_bytes -= domain_len;
    state.byte_idx += domain_len;

    // Decode the nameserver itself.
    if (nameserver_len > num_remaining_bytes) {
        if constexpr (std::same_as<Record, NS>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode NS record nameserver; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                nameserver_len,
                num_remaining_bytes
            );
        } else if constexpr (std::same_as<Record, MX>) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode MX record nameserver; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                nameserver_len,
                num_remaining_bytes
            );
        }
    }
    auto nameserver
        = std::string(reinterpret_cast<char const*>(in), nameserver_len);

    in += nameserver_len;
    num_remaining_bytes -= nameserver_len;
    state.byte_idx += nameserver_len;

    // Decode the priority, if it exists.
    std::optional<std::uint8_t> priority;
    if (has_priority) {
        if (sizeof(std::uint8_t) > num_remaining_bytes) {
            if constexpr (std::same_as<Record, NS>) {
                throw Query::DecodeError(
                    state,
                    "insufficient memory to decode NS record priority; "
                    "required size: {} bytes; "
                    "actual size: {} bytes",
                    sizeof(std::uint8_t),
                    num_remaining_bytes
                );
            } else if constexpr (std::same_as<Record, MX>) {
                throw Query::DecodeError(
                    state,
                    "insufficient memory to decode MX record priority; "
                    "required size: {} bytes; "
                    "actual size: {} bytes",
                    sizeof(std::uint8_t),
                    num_remaining_bytes
                );
            }
        }
        priority = *in++;
        num_remaining_bytes -= sizeof(std::uint8_t);
        state.byte_idx += sizeof(std::uint8_t);
    }

    return Record {
        .domain = std::move(domain),
        .name = std::move(nameserver),
        .ttl = static_cast<std::int32_t>(be32toh(ttl_no)),
        .priority = priority,
    };
}

static A decode_a(
    Query::DecodeState& state,
    std::uint8_t const*& in,
    std::size_t& num_remaining_bytes
) {
    // Does not include the domain and priority, since those are variable-length
    // and cannot be determined beforehand.
    std::size_t const record_size
        = sizeof(A::sock_addr.addr) // The IPv4 address.
        + sizeof(A::sock_addr.port) // The port.
        + sizeof(A::ttl)            // The TTL.
        + sizeof(std::uint8_t)      // Whether or not the record has a priority.
        + sizeof(std::uint8_t);     // The length of the domain.

    if (record_size > num_remaining_bytes) {
        throw Query::DecodeError(
            state,
            "insufficient memory to decode A record; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            record_size,
            num_remaining_bytes
        );
    }

    // Decode the IPv4 socket address, in network order.
    NetSockAddr sock_addr_no;
    read_bytes(&sock_addr_no.addr, in);
    in += sizeof(sock_addr_no.addr);
    read_bytes(&sock_addr_no.port, in);
    in += sizeof(sock_addr_no.port);

    // Decode the TTL, in network order.
    std::uint32_t ttl_no;
    read_bytes(&ttl_no, in);
    in += sizeof(ttl_no);

    // Decode a byte representing whether or not the record has a priority.
    bool const has_priority = *in++;

    // Decode the domain length.
    std::uint8_t const domain_len = *in++;

    num_remaining_bytes -= record_size;
    state.byte_idx += record_size;

    // Decode the domain itself.
    if (domain_len > num_remaining_bytes) {
        throw Query::DecodeError(
            state,
            "insufficient memory to decode A record domain; "
            "required size: {} bytes; "
            "actual size: {} bytes",
            domain_len,
            num_remaining_bytes
        );
    }
    auto domain = std::string(reinterpret_cast<char const*>(in), domain_len);
    in += domain_len;
    num_remaining_bytes -= domain_len;
    state.byte_idx += domain_len;

    // Decode the priority, if it exists.
    std::optional<std::uint8_t> priority;
    if (has_priority) {
        if (sizeof(std::uint8_t) > num_remaining_bytes) {
            throw Query::DecodeError(
                state,
                "insufficient memory to decode A record priority; "
                "required size: {} bytes; "
                "actual size: {} bytes",
                sizeof(std::uint8_t),
                num_remaining_bytes
            );
        }
        priority = *in++;
        num_remaining_bytes -= sizeof(std::uint8_t);
        state.byte_idx += sizeof(std::uint8_t);
    }

    return A {
        .domain = std::move(domain),
        .sock_addr = sock_addr_no.host_order(),
        .ttl = static_cast<std::int32_t>(be32toh(ttl_no)),
        .priority = priority,
    };
}

template <DNSRecord Record>
static Record decode_record(
    Query::DecodeState& state,
    std::uint8_t const*& in,
    std::size_t& num_remaining_bytes
) {
    if constexpr (std::same_as<Record, NS> or std::same_as<Record, MX>) {
        return decode_ns_or_mx<Record>(state, in, num_remaining_bytes);
    } else if constexpr (std::same_as<Record, A>) {
        return decode_a(state, in, num_remaining_bytes);
    }
}

} // namespace minidns

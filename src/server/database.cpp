#include "server/database.hpp"

#include "server/parse_error.hpp"
#include "shared/config.hpp"
#include "shared/util/split_n.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <concepts>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace minidns {

static constexpr std::string_view ENTRY_COMMENT_START = "#";
static constexpr std::string_view ENTRY_ROOT_DOMAIN = "@";
static constexpr std::string_view ENTRY_TYPE_TOKENS[] = {
    "DEFAULT",
    "SOASP",
    "SOAADMIN",
    "SOASERIAL",
    "SOAREFRESH",
    "SOARETRY",
    "SOAEXPIRE",
    "NS",
    "MX",
    "A",
    "PTR",
    "CNAME",
};

static thread_local std::filesystem::path* db_path_ptr;
static thread_local LineNum line_num;
static thread_local std::string root_domain;

static std::int32_t parse_ttl(std::string_view ttl);

static std::optional<std::uint8_t> parse_priority(std::string_view priority);

static Database::Timer parse_timer(
    Database::Tokens& tokens,
    std::vector<Database::Macro> const& macros
);

static HostSockAddr parse_sock_addr(std::string_view sock_addr);

static void expand_macro_definitions(
    Database::Tokens& tokens,
    std::vector<Database::Macro> const& macros
);

static void check_domain_len(std::string_view domain);

static void check_server_name_len(std::string_view server_name);

static std::string normalize_email_addr(std::string_view email_addr);

static std::string& append_root_domain(std::string& name);

template <typename... Args>
[[noreturn]] static void
throw_parse_error(fmt::format_string<Args...> fmt_str, Args&&... args);

template <typename Number>
    requires std::integral<Number> or std::floating_point<Number>
static Number parse_number(std::string_view name, std::string_view number);

A const& Database::CNAME::canonical() const noexcept {
    return (*this->mappings_ptr)[this->canonical_idx];
}

Database Database::from_file(std::filesystem::path&& db_path) {
    errno = 0;
    auto db_file = std::ifstream(db_path);
    if (! db_file) {
        throw fmt::system_error(
            errno,
            "failed to open database file '{}'",
            std::move(db_path).native()
        );
    }

    Database db;
    db.m_path = std::move(db_path);

    db_path_ptr = &db.m_path;
    line_num = 0;

    for (std::string buf; std::getline(db_file, buf); db.parse_line(buf)) {}

    db.m_root_domain = std::move(minidns::root_domain);

    return db;
}

std::filesystem::path const& Database::path() const noexcept {
    return m_path;
}

std::string_view Database::root_domain() const noexcept {
    return m_root_domain;
}

std::span<NS const> Database::name_servers() const noexcept {
    return m_name_servers;
}

std::span<MX const> Database::mx_servers() const noexcept {
    return m_mx_servers;
}

std::span<A const> Database::mappings() const noexcept {
    return m_mappings;
}

void Database::parse_line(std::string_view const line) {
    ++line_num;

    if (line.empty() or line.starts_with(ENTRY_COMMENT_START)) {
        return;
    }

    std::array tokens = split_n<5>(line);
    std::string_view const type = tokens[1];

    auto const match = std::ranges::find(ENTRY_TYPE_TOKENS, type);
    if (match == std::end(ENTRY_TYPE_TOKENS)) {
        throw_parse_error("unrecognized type '{}'", type);
    }

    using ParseFn = void (Database::*)(Tokens&);

    static constexpr ParseFn PARSE_FN_TABLE[] = {
        &Database::parse_macro,
        &Database::parse_primary_server,
        &Database::parse_domain_admin_email_addr,
        &Database::parse_serial_num,
        &Database::parse_refresh_interval,
        &Database::parse_retry_interval,
        &Database::parse_expiration_timer,
        &Database::parse_name_server,
        &Database::parse_mx_server,
        &Database::parse_mapping,
        &Database::parse_rev_mapping,
        &Database::parse_alias,
    };

    auto const type_idx
        = static_cast<std::size_t>(match - std::begin(ENTRY_TYPE_TOKENS));

    (this->*PARSE_FN_TABLE[type_idx])(tokens);
}

void Database::parse_macro(Tokens& tokens) {
    auto const& [name, _, val, ttl, priority] = tokens;
    if (name.empty()) {
        throw_parse_error("missing parameter");
    }
    if (val.empty()) {
        throw_parse_error("missing value");
    }
    if (not ttl.empty()) {
        throw_parse_error("unexpected TTL field");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    for (char const c : name) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            throw_parse_error("default parameter cannot contain whitespace");
        }
    }
    for (char const c : val) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            throw_parse_error("default value cannot contain whitespace");
        }
    }
    if (std::ranges::find(ENTRY_TYPE_TOKENS, name)
        != std::end(ENTRY_TYPE_TOKENS)) {
        throw_parse_error(
            "'{}' is a reserved keyword and cannot be used as a default "
            "parameter",
            name
        );
    }
    for (auto const& [k, v] : m_macros) {
        if (name == k) {
            throw_parse_error("duplicate default parameter '{}'", name);
        }
        if (val == k) {
            throw_parse_error(
                "default parameter '{}' cannot have the same value as "
                "another default parameter '{}'",
                name,
                k
            );
        }
    }
    if (name == ENTRY_ROOT_DOMAIN) {
        if (not val.ends_with('.')) {
            throw_parse_error("root domain '{}' must end with a '.'", val);
        }
        check_domain_len(val);
        if (not minidns::root_domain.empty()) {
            throw_parse_error("duplicate root domain '{}'", val);
        }
        minidns::root_domain = std::string(val);
    } else {
        m_macros.emplace_back(std::string(name), std::string(val));
    }
}

void Database::parse_primary_server(Tokens& tokens) {
    auto const& [_domain, _type, ps_name, ttl, priority] = tokens;
    if (ps_name.empty()) {
        throw_parse_error("missing primary server name");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, m_macros);
    PrimaryServer record = {
        .name = std::string(ps_name),
        .ttl = parse_ttl(ttl),
    };
    append_root_domain(record.name);
    check_server_name_len(record.name);
    m_primary_server = std::move(record);
}

void Database::parse_domain_admin_email_addr(Tokens& tokens) {
    auto const& [_domain, _type, email_addr, ttl, priority] = tokens;
    if (email_addr.empty()) {
        throw_parse_error("missing email address");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, m_macros);
    DomainAdminEmailAddr record = {
        .email_addr = normalize_email_addr(email_addr),
        .ttl = parse_ttl(ttl),
    };
    append_root_domain(record.email_addr);
    m_domain_admin_email_addr = std::move(record);
}

void Database::parse_serial_num(Tokens& tokens) {
    auto const& [_domain, _type, serial_num, ttl, priority] = tokens;
    if (serial_num.empty()) {
        throw_parse_error("missing serial number");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, m_macros);
    static constexpr std::string_view SERIAL_NUM = "serial number";
    m_serial_num = SerialNum {
        .version = parse_number<std::uint64_t>(SERIAL_NUM, serial_num),
        .ttl = parse_ttl(ttl),
    };
}

void Database::parse_refresh_interval(Tokens& tokens) {
    m_refresh_interval = parse_timer(tokens, m_macros);
}

void Database::parse_retry_interval(Tokens& tokens) {
    m_retry_interval = parse_timer(tokens, m_macros);
}

void Database::parse_expiration_timer(Tokens& tokens) {
    m_expiration_timer = parse_timer(tokens, m_macros);
}

void Database::parse_name_server(Tokens& tokens) {
    auto const& [_domain, _type, name, ttl, priority] = tokens;
    if (name.empty()) {
        throw_parse_error("missing name");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    expand_macro_definitions(tokens, m_macros);
    NS record = {
        .domain = std::string(minidns::root_domain),
        .name = std::string(name),
        .ttl = parse_ttl(ttl),
        .priority = parse_priority(priority),
    };
    append_root_domain(record.name);
    check_domain_len(record.domain);
    check_server_name_len(record.name);
    m_name_servers.push_back(std::move(record));
}

void Database::parse_mx_server(Tokens& tokens) {
    auto const& [_domain, _type, name, ttl, priority] = tokens;
    if (name.empty()) {
        throw_parse_error("missing name");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    expand_macro_definitions(tokens, m_macros);
    if (std::ranges::any_of(m_mx_servers, [name](MX const& record) {
            return record.name == name;
        })) {
        throw_parse_error("duplicate MX server '{}'", name);
    }
    MX record = {
        .domain = std::string(minidns::root_domain),
        .name = std::string(name),
        .ttl = parse_ttl(ttl),
        .priority = parse_priority(priority),
    };
    append_root_domain(record.name);
    check_domain_len(record.domain);
    check_server_name_len(record.name);
    m_mx_servers.push_back(std::move(record));
}

void Database::parse_mapping(Tokens& tokens) {
    auto const& [domain, _, sock_addr, ttl, priority] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (sock_addr.empty()) {
        throw_parse_error("missing IPv4 address");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    expand_macro_definitions(tokens, m_macros);
    if (std::ranges::any_of(m_mappings, [domain](A const& record) {
            return record.domain == domain;
        })) {
        throw_parse_error("duplicate mapping for domain '{}'", domain);
    }
    A record = {
        .domain = std::string(domain),
        .sock_addr = parse_sock_addr(sock_addr),
        .ttl = parse_ttl(ttl),
        .priority = parse_priority(priority),
    };
    append_root_domain(record.domain);
    check_domain_len(record.domain);
    m_mappings.push_back(std::move(record));
}

void Database::parse_rev_mapping(Tokens& tokens) {
    auto const& [sock_addr, _, domain, ttl, priority] = tokens;
    if (sock_addr.empty()) {
        throw_parse_error("missing IPv4 address");
    }
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, m_macros);
    HostSockAddr const sock_addr_obj = parse_sock_addr(sock_addr);
    if (std::ranges::any_of(m_rev_mappings, [sock_addr_obj](PTR const& record) {
            return record.sock_addr == sock_addr_obj;
        })) {
        throw_parse_error(
            "duplicate reverse mapping for IPv4 socket address '{}'",
            sock_addr_obj
        );
    }
    PTR record = {
        .sock_addr = sock_addr_obj,
        .domain = std::string(domain),
        .ttl = parse_ttl(ttl),
    };
    append_root_domain(record.domain);
    check_domain_len(record.domain);
    m_rev_mappings.push_back(std::move(record));
}

void Database::parse_alias(Tokens& tokens) {
    auto const& [alias, _, canonical, ttl, priority] = tokens;
    if (alias.empty()) {
        throw_parse_error("missing alias");
    }
    if (canonical.empty()) {
        throw_parse_error("missing canonical name");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, m_macros);
    for (CNAME const& record : m_aliases) {
        if (record.alias == alias) {
            throw_parse_error("duplicate alias '{}'", alias);
        }
        if (record.alias == canonical) {
            throw_parse_error(
                "canonical name '{}' cannot be an alias",
                canonical
            );
        }
    }
    auto owned_canonical = std::string(canonical);
    append_root_domain(owned_canonical);
    auto const associated_mapping
        = std::ranges::find_if(m_mappings, [&owned_canonical](A const& record) {
              return record.domain == owned_canonical;
          });
    if (associated_mapping == m_mappings.end()) {
        throw_parse_error(
            "canonical name '{}' not found in mappings",
            canonical
        );
    }
    CNAME record = {
        .alias = std::string(alias),
        .mappings_ptr = &m_mappings,
        .canonical_idx
        = static_cast<std::size_t>(associated_mapping - m_mappings.begin()),
        .ttl = parse_ttl(ttl),
    };
    m_aliases.push_back(std::move(record));
}

static std::int32_t parse_ttl(std::string_view const ttl) {
    static constexpr std::string_view TTL = "TTL";
    return parse_number<std::int32_t>(TTL, ttl);
}

static std::optional<std::uint8_t>
parse_priority(std::string_view const priority) {
    if (priority.empty()) {
        return std::nullopt;
    }
    static constexpr std::string_view PRIORITY = "priority";
    return parse_number<std::uint8_t>(PRIORITY, priority);
}

static Database::Timer parse_timer(
    Database::Tokens& tokens,
    std::vector<Database::Macro> const& macros
) {
    auto const& [_, type, timer, ttl, priority] = tokens;
    if (timer.empty()) {
        throw_parse_error("missing interval");
    }
    if (ttl.empty()) {
        throw_parse_error("missing TTL value");
    }
    if (not priority.empty()) {
        throw_parse_error("unexpected priority field");
    }
    expand_macro_definitions(tokens, macros);
    static constexpr std::string_view TIMER = "timer";
    return Database::Timer {
        .timer = {
            .tv_sec = parse_number<std::time_t>(TIMER, timer),
            .tv_usec = 0,
        },
        .ttl = parse_ttl(ttl),
    };
}

static HostSockAddr parse_sock_addr(std::string_view const sock_addr) {
    try {
        return HostSockAddr::from_str(sock_addr);
    } catch (std::invalid_argument const& err) {
        throw_parse_error("{}", err.what());
    }
}

static void expand_macro_definitions(
    Database::Tokens& tokens,
    std::vector<Database::Macro> const& macros
) {
    for (Database::Macro const& macro : macros) {
        for (std::string_view& token : tokens) {
            if (token == macro.name) {
                token = macro.value;
            }
        }
    }
}

static void check_domain_len(std::string_view const domain) {
    if (domain.length() > MAX_DOMAIN_LEN) {
        throw_parse_error(
            "domain '{}' exceeds maximum length of {} characters",
            domain,
            MAX_DOMAIN_LEN
        );
    }
}

static void check_server_name_len(std::string_view const server_name) {
    if (server_name.length() > MAX_SERVER_NAME_LEN) {
        throw_parse_error(
            "server name '{}' exceeds maximum length of {} characters",
            server_name,
            MAX_SERVER_NAME_LEN
        );
    }
}

static std::string normalize_email_addr(std::string_view const email_addr) {
    std::string result;
    result.reserve(email_addr.length());
    bool at_found = false;
    for (char const c : email_addr) {
        switch (c) {
            case '@':
                at_found = true;
                result.push_back('.');
                break;
            case '.':
                if (not at_found) {
                    result.push_back('\\');
                }
                [[fallthrough]];
            default:
                result.push_back(c);
                break;
        }
    }
    return result;
}

static std::string& append_root_domain(std::string& name) {
    if (name.ends_with('.')) {
        return name;
    }
    if (root_domain.empty()) {
        throw_parse_error(
            "name '{}' does not end with '.' and root domain was not set",
            name
        );
    }
    fmt::format_to(std::back_inserter(name), ".{}", root_domain);
    return name;
}

template <typename... Args>
[[noreturn]] static void
throw_parse_error(fmt::format_string<Args...> fmt_str, Args&&... args) {
    throw ParseError(
        std::move(*db_path_ptr),
        line_num,
        fmt_str,
        std::forward<Args>(args)...
    );
}

template <typename Number>
    requires std::integral<Number> or std::floating_point<Number>
static Number
parse_number(std::string_view const name, std::string_view const number) {
    Number result;
    char const* const number_begin = number.data();
    char const* const number_end = number_begin + number.length();
    auto const [end_ptr, err]
        = std::from_chars(number_begin, number_end, result);
    if (err != std::errc() or end_ptr != number_end) {
        switch (err) {
            case std::errc::result_out_of_range:
                throw_parse_error("{} {} out of range", name, number);
            default:
                throw_parse_error("invalid {} '{}'", name, number);
        }
    }
    return result;
}

} // namespace minidns

#include "server/server_config.hpp"

#include "server/parse_error.hpp"
#include "shared/config.hpp"
#include "shared/util/split_n.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <fmt/format.h>
#include <fstream>
#include <stdexcept>

namespace minidns {

static constexpr std::string_view ENTRY_COMMENT_START = "#";
static constexpr std::string_view ENTRY_PARAM_COMMON_LOG = "all";
static constexpr std::string_view ENTRY_PARAM_ROOT_SERVERS = "root";
static constexpr std::string_view ENTRY_TYPE_TOKENS[]
    = {"DB", "LG", "ST", "SP", "SS", "DD"};

static thread_local std::filesystem::path* config_path_ptr;
static thread_local LineNum line_num;

static HostSockAddr parse_sock_addr(std::string_view sock_addr);

static void check_domain_len(std::string_view domain);

template <typename... Args>
[[noreturn]] static void
throw_parse_error(fmt::format_string<Args...> fmt_str, Args&&... args);

ServerConfig::ServerConfig() noexcept = default;

ServerConfig ServerConfig::from_file(std::filesystem::path&& config_path) {
    auto config_file = std::ifstream(config_path);
    if (! config_file) {
        throw fmt::system_error(
            errno,
            "failed to open configuration file '{}'",
            std::move(config_path).native()
        );
    }

    ServerConfig config;
    config.m_path = std::move(config_path);

    config_path_ptr = &config.m_path;
    line_num = 0;

    for (std::string buf; std::getline(config_file, buf);
         config.parse_line(buf)) {}

    return config;
}

std::filesystem::path const& ServerConfig::path() const noexcept {
    return m_path;
}

std::filesystem::path const&
ServerConfig::root_servers_db_path() const noexcept {
    return m_root_servers_db_path;
}

std::filesystem::path const& ServerConfig::common_log_path() const noexcept {
    return m_common_log_path;
}

std::filesystem::path const& ServerConfig::domain_log_path() const noexcept {
    return m_domain_log_path;
}

std::pair<ServerConfig::Domain, std::filesystem::path> const&
ServerConfig::database_path() const noexcept {
    return m_database_path;
}

std::pair<ServerConfig::Domain, HostSockAddr> const&
ServerConfig::primary_server() const noexcept {
    return m_primary_server;
}

std::span<HostSockAddr const> ServerConfig::secondary_servers() const noexcept {
    return m_secondary_servers;
}

std::span<std::pair<ServerConfig::Domain, HostSockAddr> const>
ServerConfig::trusted_servers() const noexcept {
    return m_trusted_servers;
}

void ServerConfig::parse_line(std::string_view const line) {
    ++line_num;

    if (line.empty() or line.starts_with(ENTRY_COMMENT_START)) {
        return;
    }

    std::array const tokens = split_n<3>(line);
    std::string_view const type = tokens[1];

    auto const match = std::ranges::find(ENTRY_TYPE_TOKENS, type);
    if (match == std::end(ENTRY_TYPE_TOKENS)) {
        throw_parse_error("unrecognized type '{}'", type);
    }

    using ParseFn = void (ServerConfig::*)(Tokens const&);

    static constexpr ParseFn PARSE_FN_TABLE[] = {
        &ServerConfig::parse_database_path,
        &ServerConfig::parse_log_path,
        &ServerConfig::parse_root_servers_db_path,
        &ServerConfig::parse_primary_server,
        &ServerConfig::parse_secondary_server,
        &ServerConfig::parse_trusted_server,
    };

    auto const type_idx
        = static_cast<std::size_t>(match - std::begin(ENTRY_TYPE_TOKENS));
    (this->*PARSE_FN_TABLE[type_idx])(tokens);
}

void ServerConfig::parse_log_path(Tokens const& tokens) {
    auto& [domain, _, log_path] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (log_path.empty()) {
        throw_parse_error("missing log file path");
    }
    if (domain == ENTRY_PARAM_COMMON_LOG) {
        if (not m_common_log_path.empty()) {
            throw_parse_error("duplicate common log file path");
        }
        m_common_log_path = log_path;
    } else {
        check_domain_len(domain);
        if (not m_domain_log_path.empty()) {
            throw_parse_error("duplicate domain log file path");
        }
        m_domain_log_path = log_path;
    }
}

void ServerConfig::parse_root_servers_db_path(Tokens const& tokens) {
    auto& [root_str, _, root_servers_db_path] = tokens;
    if (root_str.empty()) {
        throw_parse_error(
            "missing root servers parameter, expected '{}'",
            ENTRY_PARAM_ROOT_SERVERS
        );
    }
    if (root_servers_db_path.empty()) {
        throw_parse_error("missing root servers file path");
    }
    if (root_str != ENTRY_PARAM_ROOT_SERVERS) {
        throw_parse_error(
            "invalid root servers parameter '{}', expected '{}'",
            root_str,
            ENTRY_PARAM_ROOT_SERVERS
        );
    }
    if (not m_root_servers_db_path.empty()) {
        throw_parse_error("duplicate root servers file path");
    }
    m_root_servers_db_path = root_servers_db_path;
}

void ServerConfig::parse_database_path(Tokens const& tokens) {
    auto& [domain, _, database_path] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (database_path.empty()) {
        throw_parse_error("missing database file path");
    }
    if (not m_database_path.second.empty()) {
        throw_parse_error("duplicate database file path");
    }
    check_domain_len(domain);
    m_database_path = std::pair(std::string(domain), database_path);
}

void ServerConfig::parse_primary_server(Tokens const& tokens) {
    auto& [domain, _, sock_addr_str] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (sock_addr_str.empty()) {
        throw_parse_error("missing server address");
    }
    check_domain_len(domain);
    if (not m_primary_server.first.empty()) {
        throw_parse_error("duplicate primary server for domain '{}'", domain);
    }
    m_primary_server
        = std::pair(std::string(domain), parse_sock_addr(sock_addr_str));
}

void ServerConfig::parse_secondary_server(Tokens const& tokens) {
    auto& [domain, _, sock_addr_str] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (sock_addr_str.empty()) {
        throw_parse_error("missing server address");
    }
    check_domain_len(domain);
    HostSockAddr const sock_addr = parse_sock_addr(sock_addr_str);
    auto const match = std::ranges::find_if(
        m_secondary_servers,
        [domain, sock_addr](HostSockAddr const secondary_server_addr) {
            return secondary_server_addr == sock_addr;
        }
    );
    if (match != m_secondary_servers.end()) {
        throw_parse_error("duplicate secondary server for domain '{}'", domain);
    }
    m_secondary_servers.emplace_back(sock_addr);
}

void ServerConfig::parse_trusted_server(Tokens const& tokens) {
    auto& [domain, _, sock_addr_str] = tokens;
    if (domain.empty()) {
        throw_parse_error("missing domain");
    }
    if (sock_addr_str.empty()) {
        throw_parse_error("missing server address");
    }
    check_domain_len(domain);
    HostSockAddr const sock_addr = parse_sock_addr(sock_addr_str);
    auto const match = std::ranges::find_if(
        m_trusted_servers,
        [domain, sock_addr](auto const& domain_and_addr) {
            return domain_and_addr.first == domain
               and domain_and_addr.second == sock_addr;
        }
    );
    if (match != m_trusted_servers.end()) {
        throw_parse_error("duplicate trusted server for domain '{}'", domain);
    }
    m_trusted_servers.emplace_back(domain, sock_addr);
}

static HostSockAddr parse_sock_addr(std::string_view const sock_addr) {
    try {
        return HostSockAddr::from_str(sock_addr);
    } catch (std::invalid_argument const& err) {
        throw_parse_error("{}", err.what());
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

template <typename... Args>
[[noreturn]] static void
throw_parse_error(fmt::format_string<Args...> fmt_str, Args&&... args) {
    throw ParseError(
        std::move(*config_path_ptr),
        line_num,
        fmt_str,
        std::forward<Args>(args)...
    );
}

} // namespace minidns

#pragma once

#include "shared/sock_addr.hpp"

#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace minidns {

class ServerConfig final {
  public:
    using Domain = std::string;

  private:
    std::filesystem::path m_path; // path to the file we parsed from.

    std::filesystem::path m_root_servers_db_path;                   // ST
    std::filesystem::path m_common_log_path;                        // all LG
    std::filesystem::path m_domain_log_path;                        // LG
    std::pair<Domain, std::filesystem::path> m_database_path;       // DB
    std::pair<Domain, HostSockAddr> m_primary_server;               // SP
    std::vector<HostSockAddr> m_secondary_servers;                  // SS
    std::vector<std::pair<Domain, HostSockAddr>> m_trusted_servers; // DD

    using Tokens = std::array<std::string_view, 3>;

    ServerConfig() noexcept;

    void parse_line(std::string_view line);
    void parse_log_path(Tokens const& tokens);
    void parse_root_servers_db_path(Tokens const& tokens);
    void parse_database_path(Tokens const& tokens);
    void parse_primary_server(Tokens const& tokens);
    void parse_secondary_server(Tokens const& tokens);
    void parse_trusted_server(Tokens const& tokens);

  public:
    static ServerConfig from_file(std::filesystem::path&& config_path);

    std::filesystem::path const& path() const noexcept;
    std::filesystem::path const& root_servers_db_path() const noexcept;
    std::filesystem::path const& common_log_path() const noexcept;
    std::filesystem::path const& domain_log_path() const noexcept;

    std::pair<Domain, std::filesystem::path> const&
    database_path() const noexcept;

    std::pair<Domain, HostSockAddr> const& primary_server() const noexcept;

    std::span<HostSockAddr const> secondary_servers() const noexcept;

    std::span<std::pair<Domain, HostSockAddr> const>
    trusted_servers() const noexcept;
};

} // namespace minidns

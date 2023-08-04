#pragma once

#include "shared/dns_record.hpp"
#include "shared/sock_addr.hpp"
#include "shared/util/strerror_mt.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include <sys/time.h>
}

namespace minidns {

class Database final {
  private:
    friend fmt::formatter<Database>;

  public:
    using Tokens = std::array<std::string_view, 5>;

    struct Macro final {
        std::string name;
        std::string value;
    };

    struct PrimaryServer final {
        std::string name;
        std::int32_t ttl;
    };

    struct DomainAdminEmailAddr final {
        std::string email_addr;
        std::int32_t ttl;
    };

    struct SerialNum final {
        std::uint64_t version;
        std::int32_t ttl;
    };

    struct Timer final {
        timeval timer;
        std::int32_t ttl;
    };

    struct CNAME final {
        std::string alias;
        std::vector<A> const* mappings_ptr;
        std::size_t canonical_idx;
        std::int32_t ttl;
        A const& canonical() const noexcept;
    };

  private:
    std::filesystem::path m_path; // path to the file we parsed from.

    std::string m_root_domain;                      // @
    std::vector<Macro> m_macros;                    // DEFAULT
    PrimaryServer m_primary_server;                 // SOASP
    DomainAdminEmailAddr m_domain_admin_email_addr; // SOAADMIN
    SerialNum m_serial_num;                         // SOASERIAL
    Timer m_refresh_interval;                       // SOAREFRESH
    Timer m_retry_interval;                         // SOARETRY
    Timer m_expiration_timer;                       // SOAEXPIRE
    std::vector<NS> m_name_servers;                 // NS
    std::vector<MX> m_mx_servers;                   // MX
    std::vector<A> m_mappings;                      // A
    std::vector<PTR> m_rev_mappings;                // PTR
    std::vector<CNAME> m_aliases;                   // CNAME

    void parse_line(std::string_view line);

    // Tokens are passed by mutable reference so macros can be expanded.
    void parse_macro(Tokens& tokens);

    void parse_primary_server(Tokens& tokens);

    void parse_domain_admin_email_addr(Tokens& tokens);

    void parse_serial_num(Tokens& tokens);

    void parse_refresh_interval(Tokens& tokens);

    void parse_retry_interval(Tokens& tokens);

    void parse_expiration_timer(Tokens& tokens);

    void parse_name_server(Tokens& tokens);

    void parse_mx_server(Tokens& tokens);

    void parse_mapping(Tokens& tokens);

    void parse_rev_mapping(Tokens& tokens);

    void parse_alias(Tokens& tokens);

  public:
    static Database from_file(std::filesystem::path&& db_path);

    std::filesystem::path const& path() const noexcept;

    std::string_view root_domain() const noexcept;
    std::span<NS const> name_servers() const noexcept;
    std::span<MX const> mx_servers() const noexcept;
    std::span<A const> mappings() const noexcept;
};

} // namespace minidns

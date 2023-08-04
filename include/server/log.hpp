#pragma once

#include "shared/query.hpp"
#include "shared/sock_addr.hpp"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string_view>

extern "C" {
#include <netinet/in.h>
#include <sys/time.h>
}

namespace minidns {

class Log final {
  public:
    enum class Level {
        OFF,
        INFO,
        WARN,
        ERROR,
        FATAL,
    };

    Log() = delete;
    Log(Log const&) = delete;
    Log(Log&&) = delete;
    Log& operator=(Log const&) = delete;
    Log& operator=(Log&&) = delete;

    static void set_level(Level lvl);

    static void set_common_log(std::filesystem::path const& path);

    static void set_domain_log(std::filesystem::path const& path);

    static void flush_on(Level lvl);

    static void info(std::string_view what);

    static void domain_info(std::string_view what);

    static void
    started(in_port_t port, std::chrono::milliseconds timeout, bool verbose);

    static void stopped(std::string_view reason);

    static void aborted(std::string_view reason);

    static void query_sent(Query const& query, HostSockAddr dest);

    static void query_received(Query const& query, HostSockAddr src);

    static void response_sent(Query const& response, HostSockAddr dest);

    static void response_received(Query const& response, HostSockAddr src);

    static void zone_transfer_complete(
        bool primary_server,
        HostSockAddr peer,
        std::chrono::milliseconds duration,
        size_t bytes_transferred
    );

    static void time_out(std::string_view reason, HostSockAddr peer);

    static void encode_error(
        Query const& query,
        std::string_view reason,
        HostSockAddr dest
    );

    static void decode_error(std::string_view reason, HostSockAddr src);

    static void zone_transfer_error(bool primary_server, HostSockAddr peer);

    static void error(std::string_view what);

    static void domain_error(std::string_view what);

    static void fatal_error(std::string_view what);
};

} // namespace minidns

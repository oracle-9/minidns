#include "shared/config.hpp"
#include "shared/query.hpp"
#include "shared/sock_addr.hpp"
#include "shared/util/scope_guard.hpp"
#include "shared/util/strerror_mt.hpp"
#include "shared/util/term_color.hpp"

#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cxxopts.hpp>
#include <fmt/core.h>
#include <fmt/format.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <system_error>

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
}

using namespace minidns;
using namespace fmt::literals;

static auto cli_config = cxxopts::Options(CLIENT_PROG_NAME);

int main(int argc, char* argv[]) try {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // clang-format off
    cli_config.add_options()
    (
        "help",
        "Display this information."
    )
    (
        "version",
        "Display version information."
    )
    (
        "verbose",
        "Enable verbose output.",
        cxxopts::value<bool>()->default_value("false")
    )
    (
        "ip",
        "Specify the DNS server IPv4 address.",
        cxxopts::value<std::string>()
    )
    (
        "port",
        "Specify the DNS server port.",
        cxxopts::value<std::string>()->default_value(DEFAULT_PORT_STR)
    )
    (
        "domain",
        "Specify the domain.",
        cxxopts::value<std::string>()
    )
    (
        "type",
        "Specify the DNS query type.",
        cxxopts::value<std::string>()
    )
    (
        "recursive",
        "Specify wether recursion is desired.",
        cxxopts::value<bool>()->default_value("false")
    )
    ;
    // clang-format on

    cxxopts::ParseResult const cli_options = cli_config.parse(argc, argv);

    if (cli_options.count("help") > 0) {
        fmt::print("{}\n", cli_config.help());
        return EXIT_SUCCESS;
    }

    if (cli_options.count("version") > 0) {
        using namespace fmt::literals;
        fmt::print(
            "{prog_name} {major}.{minor}.{patch}\n",
            "prog_name"_a = CLIENT_PROG_NAME,
            "major"_a = CLIENT_VERSION_MAJOR,
            "minor"_a = CLIENT_VERSION_MINOR,
            "patch"_a = CLIENT_VERSION_PATCH
        );
        return EXIT_SUCCESS;
    }

    bool const verbose = cli_options["verbose"].as<bool>();
    spdlog::level::level_enum const log_level
        = verbose ? spdlog::level::info : spdlog::level::warn;
    spdlog::set_level(log_level);
    spdlog::flush_on(log_level);

    auto const& server_ip = cli_options["ip"].as<std::string>();
    auto const& server_port = cli_options["port"].as<std::string>();
    auto const& domain = cli_options["domain"].as<std::string>();
    auto const& query_type_name = cli_options["type"].as<std::string>();
    auto const recursive = cli_options["recursive"].as<bool>();

    if (cli_options.count("port") == 0) {
        spdlog::info("Port not provided, using default {}.", DEFAULT_PORT);
    }

    sockaddr_in server_inet_sock_addr_no = {};
    server_inet_sock_addr_no.sin_family = AF_INET;
    if (inet_pton(
            AF_INET,
            server_ip.c_str(),
            &server_inet_sock_addr_no.sin_addr
        )
        != 1) {
        throw std::invalid_argument("invalid IPv4 address");
    }

    char const* const port_begin = server_port.c_str();
    char const* const port_end = port_begin + server_port.length();
    auto const [end, err] = std::from_chars(
        port_begin,
        port_end,
        server_inet_sock_addr_no.sin_port
    );
    if (err != std::errc() or end != port_end) {
        switch (err) {
            case std::errc::result_out_of_range:
                throw std::invalid_argument("port out of range");
            default:
                throw std::invalid_argument("invalid port");
        }
    }
    server_inet_sock_addr_no.sin_port
        = htons(server_inet_sock_addr_no.sin_port);

    HostSockAddr const server_inet_sock_addr_ho
        = NetSockAddr::from_native(server_inet_sock_addr_no).host_order();

    Query::Type query_type;
    if (! Query::str_to_type(query_type_name, query_type)) {
        throw std::invalid_argument("invalid query type");
    }

    auto query_flags = Query::Flags::QUERY;
    if (recursive) {
        query_flags |= Query::Flags::RECURSIVE;
    }

    auto query
        = Query::from_client(std::string(domain), query_type, query_flags);

    int const sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        throw fmt::system_error(errno, "failed to create socket");
    }
    spdlog::info("Created socket {}.", sock);

    ScopeGuard const _sock_guard = [sock] {
        if (close(sock) == -1) {
            spdlog::error(
                "failed to close socket {}: {}",
                sock,
                strerror_mt(errno)
            );
        }
    };

    std::uint8_t msg_buf[MAX_PDU_SIZE] = {};
    std::size_t const msg_size = query.encode_to(msg_buf);
    spdlog::info("Encoded query into {} bytes.", msg_size);
    ssize_t const send_res = sendto(
        sock,
        msg_buf,
        msg_size,
        0,
        reinterpret_cast<sockaddr const*>(&server_inet_sock_addr_no),
        sizeof(server_inet_sock_addr_no)
    );
    if (send_res == -1) {
        throw fmt::system_error(
            errno,
            "failed to send query to server at {} from socket {}",
            server_inet_sock_addr_ho,
            sock
        );
    }
    spdlog::info("Sent query.");

    spdlog::info("Waiting for response...");
    ssize_t const recv_res
        = recvfrom(sock, msg_buf, std::size(msg_buf), 0, nullptr, nullptr);

    if (recv_res == -1) {
        throw fmt::system_error(
            errno,
            "failed to receive response from server at {} from socket {}",
            server_inet_sock_addr_ho,
            sock
        );
    }
    spdlog::info("Received response.");

    query.decode_from(msg_buf);
    spdlog::info("Decoded response.");

    fmt::print("{:v}\n", query);
} catch (std::exception const& err) {
    fmt::print(
        stderr,
        "{prog_name}: {error}: {reason}.\n",
        "prog_name"_a = bold_white(CLIENT_PROG_NAME),
        "error"_a = bold_red("error"),
        "reason"_a = err.what()
    );
    auto const cli_err = dynamic_cast<cxxopts::OptionException const*>(&err);
    if (cli_err != nullptr) {
        fmt::print(stderr, "{}\n", cli_config.help());
    }
    return EXIT_FAILURE;
}

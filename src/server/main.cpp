#include "server/dns_resolver.hpp"
#include "server/log.hpp"
#include "server/primary_server.hpp"
#include "server/secondary_server.hpp"
#include "shared/config.hpp"
#include "shared/query.hpp"
#include "shared/util/term_color.hpp"

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cxxopts.hpp>
#include <exception>
#include <filesystem>
#include <fmt/core.h>
#include <fmt/format.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

extern "C" {
#include <netinet/in.h>
#include <sys/time.h>
}

using namespace minidns;
using namespace fmt::literals;

static auto cli_config = cxxopts::Options(SERVER_PROG_NAME);

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
        cxxopts::value<bool>()->default_value("true")
    )
    (
        "type",
        "Specify the server type (resolve, primary, secondary).",
        cxxopts::value<std::string>()
    )
    (
        "port",
        "Specify the DNS server port.",
        cxxopts::value<std::string>()->default_value(DEFAULT_PORT_STR)
    )
    (
        "config",
        "Specify the path to the configuration file.",
        cxxopts::value<std::filesystem::path>()
    )
    (
        "timeout",
        "Specify the timeout in milliseconds.",
        cxxopts::value<std::string>()
    )
    ;
    // clang-format on

    cxxopts::ParseResult const cli_options = cli_config.parse(argc, argv);

    if (cli_options.count("help") > 0) {
        fmt::print("{}\n", cli_config.help());
        return EXIT_SUCCESS;
    }

    if (cli_options.count("version") > 0) {
        fmt::print(
            "{prog_name} {major}.{minor}.{patch}\n",
            "prog_name"_a = SERVER_PROG_NAME,
            "major"_a = SERVER_VERSION_MAJOR,
            "minor"_a = SERVER_VERSION_MINOR,
            "patch"_a = SERVER_VERSION_PATCH
        );
        return EXIT_SUCCESS;
    }

    auto const verbose = cli_options["verbose"].as<bool>();
    auto const& type = cli_options["type"].as<std::string>();
    auto const& config_path = cli_options["config"].as<std::filesystem::path>();

    Log::set_level(verbose ? Log::Level::INFO : Log::Level::WARN);

    in_port_t port;
    if (cli_options.count("port") > 0) {
        auto const& port_str = cli_options["port"].as<std::string>();
        char const* const port_begin = port_str.c_str();
        char const* const port_end = port_begin + port_str.length();
        auto const [end, err] = std::from_chars(port_begin, port_end, port);
        if (err != std::errc() or end != port_end) {
            switch (err) {
                case std::errc::result_out_of_range:
                    throw std::invalid_argument("port out of range");
                default:
                    throw std::invalid_argument("invalid port");
            }
        }
    } else {
        port = DEFAULT_PORT;
    }

    timeval timeout;
    if (cli_options.count("timeout") > 0) {
        auto const& timeout_str = cli_options["timeout"].as<std::string>();
        char const* const timeout_begin = timeout_str.c_str();
        char const* const timeout_end = timeout_begin + timeout_str.length();
        auto const [end, err]
            = std::from_chars(timeout_begin, timeout_end, timeout.tv_sec);
        if (err != std::errc() or end != timeout_end) {
            switch (err) {
                case std::errc::result_out_of_range:
                    throw std::invalid_argument("timeout out of range");
                default:
                    throw std::invalid_argument("invalid timeout");
            }
        }
        timeout.tv_usec = (timeout.tv_sec % 1000) * 1000;
        timeout.tv_sec /= 1000;
    } else {
        timeout = DEFAULT_SERVER_TIMEOUT;
    }

    if (type == "resolver") {
        start_dns_resolver(
            std::filesystem::path(config_path),
            port,
            timeout,
            verbose
        );
    } else if (type == "primary") {
        start_primary_server(
            std::filesystem::path(config_path),
            port,
            timeout,
            verbose
        );
    } else if (type == "secondary") {
        start_secondary_resolver(
            std::filesystem::path(config_path),
            port,
            timeout,
            verbose
        );
    } else {
        throw std::invalid_argument("invalid server type");
    }
} catch (std::exception const& err) {
    fmt::print(
        stderr,
        "{prog_name}: {error}: {reason}.\n",
        "prog_name"_a = bold_white(SERVER_PROG_NAME),
        "error"_a = bold_red("error"),
        "reason"_a = err.what()
    );
    auto const cli_err = dynamic_cast<cxxopts::OptionException const*>(&err);
    if (cli_err != nullptr) {
        fmt::print(stderr, "{}\n", cli_config.help());
    }
    return EXIT_FAILURE;
}

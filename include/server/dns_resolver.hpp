#pragma once

#include <filesystem>

extern "C" {
#include <netinet/in.h>
#include <sys/time.h>
}

namespace minidns {

void start_dns_resolver(
    std::filesystem::path&& config_path,
    in_port_t port,
    timeval timeout,
    bool verbose
);

} // namespace minidns

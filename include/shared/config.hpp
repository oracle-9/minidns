#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
#include <netinet/in.h>
#include <sys/time.h>
}

namespace minidns {

inline constexpr char CLIENT_PROG_NAME[] = "minidns";
inline constexpr char SERVER_PROG_NAME[] = "minidnsd";

inline constexpr std::uint16_t CLIENT_VERSION_MAJOR = 0;
inline constexpr std::uint16_t CLIENT_VERSION_MINOR = 1;
inline constexpr std::uint16_t CLIENT_VERSION_PATCH = 0;

inline constexpr std::uint16_t SERVER_VERSION_MAJOR = 0;
inline constexpr std::uint16_t SERVER_VERSION_MINOR = 1;
inline constexpr std::uint16_t SERVER_VERSION_PATCH = 0;

inline constexpr in_port_t DEFAULT_PORT = 5353;
inline constexpr char DEFAULT_PORT_STR[] = "5353";
inline constexpr timeval DEFAULT_SERVER_TIMEOUT = {.tv_sec = 20, .tv_usec = 0};

inline constexpr std::size_t MAX_PDU_SIZE = 1024;
inline constexpr std::size_t MAX_DOMAIN_LEN = 255;
inline constexpr std::size_t MAX_SERVER_NAME_LEN = 255;

inline constexpr int TCP_BACKLOG = 10;

} // namespace minidns

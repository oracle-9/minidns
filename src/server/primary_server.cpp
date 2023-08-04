// strsignal()
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "server/primary_server.hpp"

#include "server/database.hpp"
#include "server/log.hpp"
#include "server/root_servers_database.hpp"
#include "server/server_config.hpp"
#include "shared/config.hpp"
#include "shared/dns_record.hpp"
#include "shared/query.hpp"
#include "shared/sock_addr.hpp"
#include "shared/util/scope_guard.hpp"
#include "shared/util/strerror_mt.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fmt/format.h>
#include <span>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

extern "C" {
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
}

namespace minidns {

using namespace fmt::literals;

static void handle_udp(Database const& database, int udp_sock);

static void handle_tcp(
    timeval timeout,
    std::chrono::milliseconds timeout_ms,
    Database const& database,
    int tcp_sock
);

void start_primary_server(
    std::filesystem::path&& config_path,
    in_port_t const port,
    timeval const timeout,
    bool const verbose
) try {
    auto const timeout_ms
        = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(timeout.tv_sec)
            + std::chrono::microseconds(timeout.tv_usec)
        );

    auto const config
        = ServerConfig::from_file(std::filesystem::path(config_path));
    Log::info(
        fmt::format("configuration file '{}' parsed", config_path.native())
    );

    std::filesystem::path const& common_log_path = config.common_log_path();
    std::filesystem::path const& domain_log_path = config.domain_log_path();

    Log::set_common_log(common_log_path);
    Log::info(
        fmt::format("common log file '{}' opened", common_log_path.native())
    );

    Log::set_domain_log(config.domain_log_path());
    Log::info(
        fmt::format("domain log file '{}' opened", domain_log_path.native())
    );

    auto const database = Database::from_file(
        std::filesystem::path(config.database_path().second)
    );
    Log::info(fmt::format("database file '{}' parsed", database.path().native())
    );

    auto const root_servers_db = RootServersDatabase::from_file(
        std::filesystem::path(config.root_servers_db_path())
    );
    Log::info(fmt::format(
        "root servers database file '{}' parsed",
        config.root_servers_db_path().native()
    ));

    sockaddr_in const addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = INADDR_ANY},
        .sin_zero = {},
    };

    errno = 0;
    int const udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == -1) {
        throw std::system_error(
            errno,
            std::system_category(),
            "failed to create UDP socket"
        );
    }
    Log::info(fmt::format("UDP socket created with descriptor {}", udp_sock));

    errno = 0;
    int const tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == -1) {
        throw std::system_error(
            errno,
            std::system_category(),
            "failed to create TCP socket"
        );
    }

    ScopeGuard const _udp_sock_guard = [udp_sock] {
        errno = 0;
        if (close(udp_sock) == -1) {
            Log::error(fmt::format(
                "failed to close UDP socket: {}",
                strerror_mt(errno)
            ));
        }
    };

    ScopeGuard const _tcp_sock_guard = [tcp_sock] {
        errno = 0;
        if (close(tcp_sock) == -1) {
            Log::error(fmt::format(
                "failed to close TCP socket: {}",
                strerror_mt(errno)
            ));
        }
    };

    errno = 0;
    if (bind(udp_sock, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr))
        == -1) {
        throw std::system_error(
            errno,
            std::system_category(),
            "failed to bind UDP socket"
        );
    }
    Log::info(fmt::format("UDP socket bound to port {}", port));

    errno = 0;
    if (bind(tcp_sock, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr))
        == -1) {
        throw std::system_error(
            errno,
            std::system_category(),
            "failed to bind TCP socket"
        );
    }
    Log::info(fmt::format("TCP socket bound to port {}", port));

    errno = 0;
    if (listen(tcp_sock, TCP_BACKLOG) == -1) {
        throw std::system_error(
            errno,
            std::system_category(),
            "failed to listen on TCP socket"
        );
    }
    Log::info(fmt::format("TCP socket listening on port {}", port));

    Log::started(port, timeout_ms, verbose);

    auto udp_handler = std::thread(handle_udp, database, udp_sock);
    auto tcp_handler
        = std::thread(handle_tcp, timeout, timeout_ms, database, tcp_sock);

    tcp_handler.join();
    udp_handler.join();

    Log::stopped("shutting down");
} catch (std::exception const& err) {
    Log::fatal_error(err.what());
    Log::aborted("stopping because of previous error");
    throw;
}

static void handle_udp(Database const& database, int const udp_sock) {
    std::uint8_t msg_buf[MAX_PDU_SIZE] = {};
    for (;;) {
        sockaddr_in src_addr_no = {};
        socklen_t src_addr_no_len = sizeof(src_addr_no);
        ssize_t recv_res;
        for (;;) {
            errno = 0;
            recv_res = recvfrom(
                udp_sock,
                msg_buf,
                std::size(msg_buf),
                0,
                reinterpret_cast<sockaddr*>(&src_addr_no),
                &src_addr_no_len
            );
            if (recv_res == -1) {
                Log::error(fmt::format(
                    "failed to receive data on UDP socket: {}",
                    strerror_mt(errno)
                ));
                continue;
            }
            break;
        }
        std::thread([&database, udp_sock, msg_buf, src_addr_no]() mutable {
            HostSockAddr const src_addr_ho
                = NetSockAddr::from_native(src_addr_no).host_order();
            Query query;
            try {
                query.decode_from(msg_buf);
                Log::query_received(query, src_addr_ho);
                switch (query.type) {
                    using Type = Query::Type;
                    case Type::NS:
                        {
                            std::vector<NS> vals;
                            for (NS const& name_server :
                                 database.name_servers()) {
                                if (name_server.name.ends_with(query.domain)) {
                                    vals.push_back(name_server);
                                }
                            }
                            query.vals = std::move(vals);
                            break;
                        }
                    case Type::A:
                        {
                            std::vector<A> vals;
                            for (A const& mapping : database.mappings()) {
                                if (mapping.domain.ends_with(query.domain)) {
                                    vals.push_back(mapping);
                                }
                            }
                            query.vals = std::move(vals);
                            break;
                        }
                        break;
                    case Type::MX:
                        {
                            std::vector<MX> vals;
                            for (MX const& mx_server : database.mx_servers()) {
                                if (mx_server.name.ends_with(query.domain)) {
                                    vals.push_back(mx_server);
                                }
                            }
                            query.vals = std::move(vals);
                            break;
                        }
                    default:
                        break;
                }
                for (NS const& name_server : database.name_servers()) {
                    if (name_server.name.ends_with(query.domain)) {
                        query.auths.push_back(name_server);
                    }
                }
                for (A const& mapping : database.mappings()) {
                    if (mapping.domain.ends_with(query.domain)) {
                        query.extras.push_back(mapping);
                    }
                }
                using enum Query::Flags;
                Query::Flags flags = query.flags;
                flags |= AUTHORITATIVE;
                flags &= ~QUERY;
                query.flags = flags;
                query.id = Query::next_id(query.id);
            } catch (Query::DecodeError const& err) {
                query = Query {};
                query.rc = Query::ResponseCode::DECODE_ERR;
                Log::decode_error(err.what(), src_addr_ho);
            }
            try {
                std::size_t const msg_size = query.encode_to(msg_buf);
                errno = 0;
                ssize_t const send_res = sendto(
                    udp_sock,
                    msg_buf,
                    msg_size,
                    0,
                    reinterpret_cast<sockaddr const*>(&src_addr_no),
                    sizeof(src_addr_no)
                );
                if (send_res == -1) {
                    Log::error(fmt::format(
                        "failed to send response: {}",
                        strerror_mt(errno)
                    ));
                } else {
                    Log::response_sent(query, src_addr_ho);
                }
            } catch (Query::EncodeError const& err) {
                Log::encode_error(query, err.what(), src_addr_ho);
            }
        }).detach();
    }
}

static void handle_tcp(
    timeval const timeout,
    std::chrono::milliseconds const timeout_ms,
    Database const& database,
    int const tcp_sock
) {
    for (;;) {
        sockaddr_in src_addr_no = {};
        socklen_t src_addr_no_len = sizeof(src_addr_no);
        HostSockAddr src_addr_ho;
        int conn_sock;
        for (;;) {
            errno = 0;
            conn_sock = accept(
                tcp_sock,
                reinterpret_cast<sockaddr*>(&src_addr_no),
                &src_addr_no_len
            );
            if (conn_sock == -1) {
                Log::domain_error(fmt::format(
                    "failed to accept connection on TCP socket {}: {}",
                    tcp_sock,
                    strerror_mt(errno)
                ));
                continue;
            }
            src_addr_ho = NetSockAddr::from_native(src_addr_no).host_order();
            Log::domain_info(fmt::format(
                "accepted TCP connection from {} on socket {}",
                src_addr_ho,
                conn_sock
            ));
            break;
        }
        std::thread([timeout,
                     timeout_ms,
                     &database,
                     conn_sock,
                     src_addr_no,
                     src_addr_ho]() mutable {
            errno = 0;
            if (setsockopt(
                    conn_sock,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &timeout,
                    sizeof(timeout)
                )
                == -1) {
                Log::domain_error(fmt::format(
                    "failed to set receive timeout on TCP socket {}: {}",
                    conn_sock,
                    strerror_mt(errno)
                ));
                return;
            }
            Log::domain_info(fmt::format(
                "set receive timeout on TCP socket {} to {}",
                conn_sock,
                timeout_ms
            ));
            std::uint64_t secondary_server_db_serial;
            ssize_t recv_res;
            for (;;) {
                errno = 0;
                recv_res = recv(
                    conn_sock,
                    &secondary_server_db_serial,
                    sizeof(secondary_server_db_serial),
                    0
                );
                if (recv_res == -1) {
                    switch (errno) {
                        case ETIMEDOUT:
                            Log::time_out(
                                fmt::format(
                                    "while waiting for database serial on TCP "
                                    "socket {}: {}",
                                    conn_sock,
                                    strerror_mt(errno)
                                ),
                                src_addr_ho
                            );
                            break;
                        default:
                            Log::domain_error(fmt::format(
                                "failed to receive data on TCP socket {}: "
                                "{}",
                                conn_sock,
                                strerror_mt(errno)
                            ));
                            break;
                    }
                    Log::zone_transfer_error(true, src_addr_ho);
                    continue;
                }
            }
            if (static_cast<std::size_t>(recv_res)
                < sizeof(secondary_server_db_serial)) {
                Log::zone_transfer_error(true, src_addr_ho);
                return;
            }
        }).detach();
    }
}

} // namespace minidns

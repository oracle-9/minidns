// endian.h is not available on all platforms, so we need to define this macro.
#ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

// strtok_r() is not available on all platforms, so we need to define this
// macro.
#ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE
#endif // _POSIX_C_SOURCE

#include "server/secondary_server.hpp"

#include "server/database.hpp"
#include "server/log.hpp"
#include "server/raii_socket.hpp"
#include "server/root_servers_database.hpp"
#include "server/server_config.hpp"
#include "shared/config.hpp"
#include "shared/query.hpp"
#include "shared/sock_addr.hpp"
#include "shared/util/strerror_mt.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fmt/format.h>
#include <memory>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
// #include <span>

extern "C" {
#include <arpa/inet.h>
#include <endian.h>
#include <sys/socket.h>
#include <unistd.h>
}

namespace minidns {

struct DatabaseReplica {
    using PrimaryServer = Database::PrimaryServer;
    using DomainAdminEmailAddr = Database::DomainAdminEmailAddr;
    using SerialNum = Database::SerialNum;
    using Timer = Database::Timer;
    using CNAME = Database::CNAME;

    PrimaryServer primary_server;
    DomainAdminEmailAddr domain_admin_email_addr;
    SerialNum serial_num;
    Timer refresh_interval;
    Timer retry_interval;
    Timer expiration_timer;
    std::vector<NS> name_servers;
    std::vector<MX> mx_servers;
    std::vector<A> mappings;
    std::vector<PTR> rev_mappings;
    std::vector<CNAME> aliases;
};

namespace {
struct Context {
    ServerConfig config;
    RootServersDatabase root_servers_db;
    DatabaseReplica db_replica;
    timeval timeout;
    std::chrono::milliseconds timeout_ms;
    RAIISocket main_sock;
    RAIISocket zt_sock;
};
} // namespace

static void respond(
    std::shared_ptr<Context> ctx,
    sockaddr_in src_addr_no,
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf,
    std::size_t msg_len
);

static bool zone_transfer(Context& ctx);

void start_secondary_resolver(
    std::filesystem::path&& config_path,
    in_port_t const port,
    timeval const timeout,
    bool const verbose
) try {
    // Convert timeout to chrono::milliseconds for logging.
    auto const timeout_ms
        = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(timeout.tv_sec)
            + std::chrono::microseconds(timeout.tv_usec)
        );

    // Parse configuration file.
    auto config = ServerConfig::from_file(std::move(config_path));
    Log::info(
        fmt::format("parsed configuration file '{}'", config.path().native())
    );

    // Set common log.
    std::filesystem::path const& common_log = config.common_log_path();
    Log::set_common_log(common_log);
    Log::info(fmt::format("opened common log file '{}'", common_log.native()));

    // Set domain log.
    std::filesystem::path const& domain_log = config.domain_log_path();
    Log::set_domain_log(domain_log);
    Log::info(fmt::format("opened domain log file '{}'", domain_log.native()));

    // Parse root servers database file.
    auto root_servers_db = RootServersDatabase::from_file(
        std::filesystem::path(config.root_servers_db_path())
    );
    Log::info(fmt::format(
        "parsed root servers database file '{}'",
        root_servers_db.path().native()
    ));

    // Create main socket.
    auto main_sock = RAIISocket::from_native(socket(AF_INET, SOCK_DGRAM, 0));
    if (! main_sock) {
        throw fmt::system_error(errno, "failed to create main socket");
    }
    Log::info(fmt::format("created main socket {}", main_sock.get()));

    // Bind main socket to the specified port.
    sockaddr_in const server_addr_no = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = INADDR_ANY},
        .sin_zero = {},
    };
    if (bind(
            main_sock.get(),
            reinterpret_cast<sockaddr const*>(&server_addr_no),
            sizeof(server_addr_no)
        )
        == -1) {
        throw fmt::system_error(
            errno,
            "failed to bind main socket {} to port {}",
            main_sock.get(),
            port
        );
    }
    Log::info(
        fmt::format("bound main socket {} to port {}", main_sock.get(), port)
    );

    // Create zone transfer socket.
    auto zt_sock = RAIISocket::from_native(socket(AF_INET, SOCK_STREAM, 0));
    if (! zt_sock) {
        throw fmt::system_error(errno, "failed to create zone transfer socket");
    }
    Log::info(fmt::format("created zone transfer socket {}", zt_sock.get()));

    // Set the timeout for the zone transfer socket.
    if (setsockopt(
            zt_sock.get(),
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)
        )
        == -1) {
        throw fmt::system_error(
            errno,
            "failed to set transfer socket {} timeout to {}: {}",
            zt_sock.get(),
            timeout_ms,
            strerror_mt(errno)
        );
    }
    Log::domain_info(fmt::format(
        "set zone transfer socket {} timeout to {}",
        zt_sock.get(),
        timeout_ms
    ));

    Log::started(port, timeout_ms, verbose);

    // Store the encoded query.
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf = {};

    // Store the src address.
    sockaddr_in src_addr_no = {};
    socklen_t src_addr_len = sizeof(src_addr_no);

    // Create the context for the threads.
    // This is a shared_ptr because the threads are detached, so they may
    // continue to run even after this function returns.
    auto const ctx = std::make_shared<Context>(
        std::move(config),
        std::move(root_servers_db),
        DatabaseReplica(),
        timeout,
        timeout_ms,
        std::move(main_sock),
        std::move(zt_sock)
    );

    zone_transfer(*ctx);

    for (;;) {
        ssize_t const query_len = recvfrom(
            main_sock.get(),
            msg_buf.data(),
            msg_buf.size(),
            0,
            reinterpret_cast<sockaddr*>(&src_addr_no),
            &src_addr_len
        );
        if (query_len == -1) {
            Log::domain_error(fmt::format(
                "failed to receive data on socket {}: {}",
                main_sock.get(),
                strerror_mt(errno)
            ));
            continue;
        }
        std::thread(respond, ctx, src_addr_no, msg_buf, query_len).detach();
    }

    Log::stopped("shutting down");
} catch (std::exception const& err) {
    Log::fatal_error(err.what());
    Log::aborted("stopping because of previous error");
    throw;
}

static void respond(
    std::shared_ptr<Context> const ctx,
    sockaddr_in const src_addr_no,
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf,
    std::size_t const msg_len
) try {
    HostSockAddr const src_addr_ho
        = NetSockAddr::from_native(src_addr_no).host_order();

    // `query` stores the decoded query.
    // `response` stores the response to be sent.
    // We're defining these on this scope so we can reuse their dynamic buffers,
    // e.g. the domain, the response values, the authority values and the extra
    // values. We also use them on the exception flow, so they need to be
    // defined before the try-catch block.
    Query query, response;

    // Decode the query.
    bool failed_query_decode = false;
    try {
        query.decode_from(std::span(msg_buf.data(), msg_len));
    } catch (Query::DecodeError const& err) {
        Log::decode_error(err.what(), src_addr_ho);
        failed_query_decode = true;
    }
    if (failed_query_decode) {
        // Decode failed, fill the response with the error code DECODE_ERR.
        response.id = Query::random_id();
        response.flags = Query::Flags(0b000);
        response.rc = Query::ResponseCode::DECODE_ERR;
        response.type = Query::Type::NONE;
        response.domain.clear();
        std::visit([](auto& vals) { vals.clear(); }, response.vals);
        response.auths.clear();
        response.extras.clear();
    } else {
        // Decode succeeded.
        Log::query_received(query, src_addr_ho);
        query.id = Query::next_id(query.id);

        // Check if we can answer the query, based on the query domain.
        if (std::ranges::none_of(
                ctx->config.trusted_servers(),
                [&query](auto& domain_and_ip) {
                    return domain_and_ip.first == query.domain;
                }
            )) {
            // We can't answer the query, fill the response with the error code
            // NO_SUCH_DOMAIN.
            response.id = query.id;
            response.flags = Query::Flags(0b000);
            response.rc = Query::ResponseCode::NO_SUCH_DOMAIN;
            response.type = query.type;
            response.domain = query.domain;
            std::visit([](auto& vals) { vals.clear(); }, response.vals);
            response.auths.clear();
            response.extras.clear();
        } else {
            // We can answer the query.
            // Start by looking up a response in our database copy.
            DatabaseReplica const& database = ctx->db_replica;
            switch (query.type) {
                using Type = Query::Type;
                case Type::NS:
                    {
                        std::vector<NS> vals;
                        for (NS const& name_server : database.name_servers) {
                            if (name_server.name.ends_with(query.domain)) {
                                vals.push_back(name_server);
                            }
                        }
                        response.vals = std::move(vals);
                        break;
                    }
                case Type::A:
                    {
                        std::vector<A> vals;
                        for (A const& mapping : database.mappings) {
                            if (mapping.domain.ends_with(query.domain)) {
                                vals.push_back(mapping);
                            }
                        }
                        response.vals = std::move(vals);
                        break;
                    }
                    break;
                case Type::MX:
                    {
                        std::vector<MX> vals;
                        for (MX const& mx_server : database.mx_servers) {
                            if (mx_server.name.ends_with(query.domain)) {
                                vals.push_back(mx_server);
                            }
                        }
                        response.vals = std::move(vals);
                        break;
                    }
                default:
                    break;
            }
            for (NS const& name_server : database.name_servers) {
                if (name_server.name.ends_with(query.domain)) {
                    response.auths.push_back(name_server);
                }
            }
            for (A const& mapping : database.mappings) {
                if (mapping.domain.ends_with(query.domain)) {
                    response.extras.push_back(mapping);
                }
            }
            using enum Query::Flags;
            Query::Flags flags = query.flags;
            flags |= AUTHORITATIVE;
            flags &= ~QUERY;
            response.flags = flags;
        }
    }
    // Send the response to the source.
    std::size_t const response_len = response.encode_to(msg_buf);
    Log::response_sent(response, src_addr_ho);
    if (sendto(
            ctx->main_sock.get(),
            msg_buf.data(),
            response_len,
            0,
            reinterpret_cast<sockaddr const*>(&src_addr_no),
            sizeof(src_addr_no)
        )
        == -1) {
        // Failed to send the response to the source.
        Log::domain_error(fmt::format(
            "failed to send response on socket {} to {}: {}",
            ctx->main_sock.get(),
            src_addr_ho,
            strerror_mt(errno)
        ));
    }
    Log::response_sent(response, src_addr_ho);
} catch (Query::EncodeError const& err) {
    // If we fail to encode the response, we log the error and return.
    // There's nothing we can do to recover from this error.
    Log::domain_error(fmt::format("failed to encode response: {}", err.what()));
}

static bool zone_transfer(Context& ctx) try {
    HostSockAddr const primary_server_addr_ho
        = ctx.config.primary_server().second;
    int const zt_sock = ctx.zt_sock.get();
    if (connect(
            zt_sock,
            reinterpret_cast<sockaddr const*>(&primary_server_addr_ho),
            sizeof(primary_server_addr_ho)
        )
        == -1) {
        Log::zone_transfer_error(false, primary_server_addr_ho);
        return false;
    }
    std::uint16_t num_entries;
    if (recv(zt_sock, &num_entries, sizeof(num_entries), 0) == -1) {
        Log::zone_transfer_error(false, primary_server_addr_ho);
        return false;
    }
    num_entries = be16toh(num_entries);
    auto msg_buf = std::string(MAX_PDU_SIZE + 1, '\0');
    for (std::uint16_t i = 0; i < num_entries; ++i) {
        if (recv(zt_sock, msg_buf.data(), msg_buf.size(), 0) == -1) {
            Log::zone_transfer_error(false, primary_server_addr_ho);
            return false;
        }
        char* save_ptr;
        char const* tok = strtok_r(msg_buf.data(), " ", &save_ptr);
        std::string_view const type = tok;
        if (type == "SOASP") {
            ctx.db_replica.primary_server.name
                = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.primary_server.ttl = 0;
        } else if (type == "SOAADMIN") {
            ctx.db_replica.domain_admin_email_addr.email_addr
                = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.domain_admin_email_addr.ttl = 0;
        } else if (type == "SOASERIAL") {
            ctx.db_replica.serial_num.version
                = std::stoul(strtok_r(nullptr, " ", &save_ptr));
            ctx.db_replica.serial_num.ttl = 0;
        } else if (type == "SOAREFRESH") {
            ctx.db_replica.refresh_interval.timer = {
                .tv_sec
                = std::strtoll(strtok_r(nullptr, " ", &save_ptr), nullptr, 10),
                .tv_usec = 0,
            };
            ctx.db_replica.refresh_interval.ttl = 0;
        } else if (type == "SOARETRY") {
            ctx.db_replica.retry_interval.timer = {
                .tv_sec
                = std::strtoll(strtok_r(nullptr, " ", &save_ptr), nullptr, 10),
                .tv_usec = 0,
            };
            ctx.db_replica.retry_interval.ttl = 0;
        } else if (type == "SOAEXPIRE") {
            ctx.db_replica.expiration_timer.timer = {
                .tv_sec
                = std::strtoll(strtok_r(nullptr, " ", &save_ptr), nullptr, 10),
                .tv_usec = 0,
            };
            ctx.db_replica.expiration_timer.ttl = 0;
        } else if (type == "NS") {
            char const* const domain = strtok_r(nullptr, " ", &save_ptr);
            char const* const name = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.name_servers
                .emplace_back(domain, name, 0, std::nullopt);
        } else if (type == "MX") {
            char const* const domain = strtok_r(nullptr, " ", &save_ptr);
            char const* const name = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.mx_servers
                .emplace_back(domain, name, 0, std::nullopt);
        } else if (type == "A") {
            char const* const domain = strtok_r(nullptr, " ", &save_ptr);
            char const* const ipv4_sock_addr
                = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.mappings.emplace_back(
                domain,
                HostSockAddr::from_str(ipv4_sock_addr),
                0,
                std::nullopt
            );
        } else if (type == "PTR") {
            char const* const ipv4_sock_addr
                = strtok_r(nullptr, " ", &save_ptr);
            char const* const domain = strtok_r(nullptr, " ", &save_ptr);
            ctx.db_replica.rev_mappings.emplace_back(
                HostSockAddr::from_str(ipv4_sock_addr),
                domain,
                0
            );
        } else if (type == "CNAME") {
            char const* const alias = strtok_r(nullptr, " ", &save_ptr);
            std::size_t const canonical_idx
                = std::stoul(strtok_r(nullptr, " ", &save_ptr));
            ctx.db_replica.aliases.emplace_back(
                alias,
                &ctx.db_replica.mappings,
                canonical_idx,
                0
            );
        }
    }
    Log::zone_transfer_complete(false, primary_server_addr_ho, {}, {});
    return true;
} catch (...) {
    Log::zone_transfer_error(false, ctx.config.primary_server().second);
    return false;
}
} // namespace minidns

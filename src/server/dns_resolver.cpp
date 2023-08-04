#include "server/dns_resolver.hpp"

#include "server/log.hpp"
#include "server/raii_socket.hpp"
#include "server/root_servers_database.hpp"
#include "server/server_config.hpp"
#include "shared/config.hpp"
#include "shared/query.hpp"
#include "shared/sock_addr.hpp"
#include "shared/util/strerror_mt.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fmt/format.h>
#include <memory>
#include <span>
#include <thread>
#include <utility>

extern "C" {
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
}

namespace minidns {

namespace {
struct Context {
    ServerConfig config;
    RootServersDatabase root_servers_db;
    timeval timeout;
    std::chrono::milliseconds timeout_ms;
    RAIISocket main_sock;
};
} // namespace

static void respond(
    std::shared_ptr<Context const> ctx,
    sockaddr_in client_addr_no,
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf,
    std::size_t msg_len
);

void start_dns_resolver(
    std::filesystem::path&& config_path,
    in_port_t const port,
    timeval const timeout,
    bool const verbose
) try {
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

    // Convert timeval to chrono::milliseconds for logging.
    auto const timeout_ms
        = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(timeout.tv_sec)
            + std::chrono::microseconds(timeout.tv_usec)
        );

    Log::started(port, timeout_ms, verbose);

    // Store the encoded query.
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf = {};

    // Store the client address.
    sockaddr_in client_addr_no = {};
    socklen_t client_addr_len = sizeof(client_addr_no);

    // Create the context for the threads.
    // This is a shared_ptr because the threads are detached, so they may
    // continue to run even after this function returns.
    auto const ctx = std::make_shared<Context>(
        std::move(config),
        std::move(root_servers_db),
        timeout,
        timeout_ms,
        std::move(main_sock)
    );

    for (;;) {
        ssize_t const query_len = recvfrom(
            main_sock.get(),
            msg_buf.data(),
            msg_buf.size(),
            0,
            reinterpret_cast<sockaddr*>(&client_addr_no),
            &client_addr_len
        );
        if (query_len == -1) {
            Log::domain_error(fmt::format(
                "failed to receive data on socket {}: {}",
                main_sock.get(),
                strerror_mt(errno)
            ));
            continue;
        }
        std::thread(respond, ctx, client_addr_no, msg_buf, query_len).detach();
    }

    Log::stopped("shutting down");
} catch (std::exception const& err) {
    Log::fatal_error(err.what());
    Log::aborted("stopping because of previous error");
    throw;
}

static bool ask_dd_servers(
    Query const& query,
    std::span<std::uint8_t> query_bytes,
    ServerConfig const& config,
    int sock,
    Query& response
);

static bool ask_root_servers(
    Query const& query,
    std::span<std::uint8_t> query_bytes,
    RootServersDatabase const& root_servers_db,
    int sock,
    Query& response
);

static void respond(
    std::shared_ptr<Context const> const ctx,
    sockaddr_in const client_addr_no,
    std::array<std::uint8_t, MAX_PDU_SIZE> msg_buf,
    std::size_t const msg_len
) try {
    HostSockAddr const client_addr_ho
        = NetSockAddr::from_native(client_addr_no).host_order();

    // Create a new socket from which to forward the query to the root servers.
    auto query_sock = RAIISocket::from_native(socket(AF_INET, SOCK_DGRAM, 0));
    if (! query_sock) {
        Log::domain_error(
            fmt::format("failed to create query socket: {}", strerror_mt(errno))
        );
        return;
    }
    Log::domain_info(fmt::format("created query socket {}", query_sock.get()));

    // Set the timeout for the query socket.
    if (setsockopt(
            query_sock.get(),
            SOL_SOCKET,
            SO_RCVTIMEO,
            &(ctx->timeout),
            sizeof(ctx->timeout)
        )
        == -1) {
        Log::domain_error(fmt::format(
            "failed to set query socket {} timeout to {}: {}",
            query_sock.get(),
            ctx->timeout_ms,
            strerror_mt(errno)
        ));
        return;
    }
    Log::domain_info(fmt::format(
        "set query socket {} timeout to {}",
        query_sock.get(),
        ctx->timeout_ms
    ));

    // Bind the query socket to any available port.
    sockaddr_in query_addr_no = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr = {.s_addr = INADDR_ANY},
        .sin_zero = {},
    };
    socklen_t query_addr_len = sizeof(query_addr_no);
    if (bind(
            query_sock.get(),
            reinterpret_cast<sockaddr*>(&query_addr_no),
            query_addr_len
        )
        == -1) {
        Log::domain_error(fmt::format(
            "failed to bind query socket {}: {}",
            query_sock.get(),
            strerror_mt(errno)
        ));
        return;
    }

    // Retrieve the port assigned to the query socket.
    if (getsockname(
            query_sock.get(),
            reinterpret_cast<sockaddr*>(&query_addr_no),
            &query_addr_len
        )
        == -1) {
        Log::domain_error(fmt::format(
            "failed to retrieve port of query socket {}: {}",
            query_sock.get(),
            strerror_mt(errno)
        ));
        return;
    }
    Log::domain_info(fmt::format(
        "bound query socket {} to port {}",
        query_sock.get(),
        ntohs(query_addr_no.sin_port)
    ));

    // Now that the query socket is ready, we can start handling the query.
    // This is a bit complicated, especially because we're mixing C++ exceptions
    // and C error codes.

    // `query` stores the decoded client query.
    // `response` stores the response to be sent to the client.
    // We're defining these on this scope so we can reuse their dynamic buffers,
    // e.g. the domain, the response values, the authority values and the extra
    // values. We also use them on the exception flow, so they need to be
    // defined before the try-catch block.
    Query query, response;
    bool failed_query_decode = false;

    // First we decode the query received from the client.
    // Then we forward the query to the DD/root servers.
    // If decoding fails or the servers don't respond, we send a response to the
    // client with the appropriate error code.
    // Otherwise, we send the response to the client.

    // Decode the query received from the client.
    try {
        query.decode_from(std::span(msg_buf.data(), msg_len));
    } catch (Query::DecodeError const& err) {
        Log::decode_error(
            fmt::format("from client: {}", err.what()),
            client_addr_ho
        );
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
        // Decode succeeded, forward the query to the DD/root servers.
        Log::query_received(query, client_addr_ho);
        query.id = Query::next_id(query.id);
        auto const query_bytes
            = std::span(msg_buf.data(), query.encode_to(msg_buf));
        if (! ask_dd_servers(
                query,
                query_bytes,
                ctx->config,
                query_sock.get(),
                response
            )
            and ! ask_root_servers(
                query,
                query_bytes,
                ctx->root_servers_db,
                query_sock.get(),
                response
            )) {
            // No response from the DD/root servers, fill the response with the
            // error code NO_SUCH_DOMAIN.
            response.id = query.id;
            response.flags = query.flags & ~Query::Flags::QUERY;
            response.rc = Query::ResponseCode::NO_SUCH_DOMAIN;
            response.type = query.type;
            response.domain = query.domain;
            std::visit([](auto& vals) { vals.clear(); }, response.vals);
            response.auths.clear();
            response.extras.clear();
        }
    }
    // Send the response to the client.
    std::size_t const response_len = response.encode_to(msg_buf);
    Log::response_sent(response, client_addr_ho);
    if (sendto(
            ctx->main_sock.get(),
            msg_buf.data(),
            response_len,
            0,
            reinterpret_cast<sockaddr const*>(&client_addr_no),
            sizeof(client_addr_no)
        )
        == -1) {
        // Failed to send the response to the client.
        Log::domain_error(fmt::format(
            "failed to send response on socket {} to client {}: {}",
            ctx->main_sock.get(),
            client_addr_ho,
            strerror_mt(errno)
        ));
    }
    Log::response_sent(response, client_addr_ho);
} catch (Query::EncodeError const& err) {
    // If we fail to encode the response, we log the error and return.
    // There's nothing we can do to recover from this error.
    Log::domain_error(fmt::format("failed to encode response: {}", err.what()));
}

static bool ask_server(
    Query const& query,
    std::span<uint8_t> query_bytes,
    int const sock,
    HostSockAddr server_addr_ho,
    Query& response
);

static bool ask_dd_servers(
    Query const& query,
    std::span<std::uint8_t> const query_bytes,
    ServerConfig const& config,
    int const sock,
    Query& response
) {
    for (auto& [dd_domain, dd_server_addr_ho] : config.trusted_servers()) {
        if (query.domain == dd_domain
            and ask_server(
                query,
                query_bytes,
                sock,
                dd_server_addr_ho,
                response
            )) {
            return true;
        }
    }
    return false;
}

static bool ask_root_servers(
    Query const& query,
    std::span<std::uint8_t> const query_bytes,
    RootServersDatabase const& root_servers_db,
    int const sock,
    Query& response
) {
    for (HostSockAddr const root_server_addr_ho : root_servers_db.get()) {
        if (ask_server(
                query,
                query_bytes,
                sock,
                root_server_addr_ho,
                response
            )) {
            return true;
        }
    }
    return false;
}

static bool ask_server(
    Query const& query,
    std::span<uint8_t> const query_bytes,
    int const sock,
    HostSockAddr const server_addr_ho,
    Query& response
) {
    // Convert the server address to network byte order, so that it can be used
    // by sendto().
    sockaddr_in const server_addr_no = server_addr_ho.net_order().native();

    // Send the query to the server.
    if (sendto(
            sock,
            query_bytes.data(),
            query_bytes.size(),
            0,
            reinterpret_cast<sockaddr const*>(&server_addr_no),
            sizeof(server_addr_no)
        )
        == -1) {
        // Failed to send the query to the server.
        return false;
    }
    Log::query_sent(query, server_addr_ho);

    // Wait for a response from the server.
    std::uint8_t recv_buf[MAX_PDU_SIZE];

    // `response_addr_no` address stores the actual source address of the
    // response, which may be different from the server address we sent the
    // query to. In that case, we'll just ignore the response and wait for
    // another one.
    sockaddr_in response_addr_no = {};
    socklen_t response_addr_len = sizeof(response_addr_no);

    ssize_t response_len;
    for (;;) {
        response_len = recvfrom(
            sock,
            recv_buf,
            std::size(recv_buf),
            0,
            reinterpret_cast<sockaddr*>(&response_addr_no),
            &response_addr_len
        );
        if (response_len == -1) {
            // Failed to receive a response from a server.
            if (errno == ETIMEDOUT) {
                // Timeout error.
                Log::time_out(
                    fmt::format(
                        "waiting for response on socket {} from server",
                        sock
                    ),
                    server_addr_ho
                );
            } else {
                // Other error.
                Log::domain_error(fmt::format(
                    "failed to receive response on socket {} from server {}: "
                    "{}",
                    sock,
                    server_addr_ho,
                    strerror_mt(errno)
                ));
            }
            return false;
        }
        if (response_addr_no.sin_addr.s_addr
            == server_addr_no.sin_addr.s_addr) {
            break;
        }
        // The response source address is not the address we sent the query to.
        Log::domain_error(fmt::format(
            "expected response from server {}, but received response from {}",
            server_addr_ho,
            NetSockAddr::from_native(response_addr_no).host_order()
        ));
    }

    // Decode the response from the server.
    try {
        response.decode_from(
            std::span(recv_buf, static_cast<std::size_t>(response_len))
        );
        Log::response_received(response, server_addr_ho);
    } catch (Query::DecodeError const& err) {
        // Failed to decode a response.
        Log::decode_error(
            fmt::format("from server: {}", err.what()),
            server_addr_ho
        );
        response.id = query.id;
        response.flags = query.flags & ~Query::Flags::QUERY;
        response.rc = Query::ResponseCode::DECODE_ERR;
        response.type = query.type;
        std::visit([](auto& vals) { vals.clear(); }, response.vals);
        response.auths.clear();
        response.extras.clear();
    }
    return true;
}

} // namespace minidns

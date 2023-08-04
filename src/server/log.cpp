#include "server/log.hpp"

#include "shared/util/term_color.hpp"

#include <cerrno>
#include <cstdio>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fstream>
#include <mutex>
#include <sstream>
#include <system_error>

namespace minidns {

#undef log
#define log(file, mtx, type, term_style, fmt_string, ...)                      \
    do {                                                                       \
        std::chrono::time_point const ymdhm = now();                           \
        std::chrono::milliseconds const millis = ymdhm.time_since_epoch();     \
        auto const _guard = std::lock_guard(mtx);                              \
        fmt::print(                                                            \
            file,                                                              \
            "[{:%FT%R}:{:%S}] {} " fmt_string "\n",                            \
            ymdhm,                                                             \
            millis,                                                            \
            type __VA_OPT__(, ) __VA_ARGS__                                    \
        );                                                                     \
        fmt::print(                                                            \
            "[{:%FT%R}:{:%S}] {} " fmt_string "\n",                            \
            ymdhm,                                                             \
            millis,                                                            \
            term_style(type) __VA_OPT__(, ) __VA_ARGS__                        \
        );                                                                     \
        if (log_lvl >= flush_lvl) {                                            \
            file.flush();                                                      \
            std::fflush(stdout);                                               \
        }                                                                      \
    } while (false)

static constexpr std::string_view SP = "SP";
static constexpr std::string_view SS = "SS";
static constexpr std::string_view DEBUG = "debug";
static constexpr std::string_view SHY = "shy";

static std::filesystem::path common_log_path;
static std::filesystem::path domain_log_path;

static std::streambuf* common_log_file_buf;
static std::streambuf* domain_log_file_buf;

static std::stringbuf common_log_backtrace;
static std::stringbuf domain_log_backtrace;

static std::ofstream common_log = [] {
    std::ofstream file;
    common_log_file_buf = file.basic_ios::rdbuf(&common_log_backtrace);
    return file;
}();
static std::ofstream domain_log = [] {
    std::ofstream file;
    domain_log_file_buf = file.basic_ios::rdbuf(&domain_log_backtrace);
    return file;
}();

static std::mutex common_log_mtx;
static std::mutex domain_log_mtx;

static Log::Level log_lvl = Log::Level::INFO;
static Log::Level flush_lvl = Log::Level::WARN;

static void dispatch_stop(bool good, std::string_view reason);

static void dispatch_info(bool domain_specific, std::string_view what);

static void dispatch_error(bool domain_specific, std::string_view what);

static decltype(auto) now() {
    using namespace std::chrono;
    return floor<milliseconds>(system_clock::now());
}

static void set_log(
    std::ofstream& init,
    std::filesystem::path& old_log_path,
    std::filesystem::path const& new_log_path,
    std::streambuf* log_file_buf,
    std::stringbuf& backtrace,
    std::mutex& mtx
) {
    auto _guard = std::lock_guard(mtx);
    if (init.is_open()) {
        init.close();
        if (! init) {
            throw fmt::system_error(
                errno,
                "failed to close old log file '{}'",
                old_log_path.native()
            );
        }
    }
    old_log_path = new_log_path;
    std::string_view const backtrace_contents = backtrace.view();
    init.basic_ios::rdbuf(log_file_buf);
    std::error_code err;
    if (new_log_path.has_parent_path()) {
        std::filesystem::create_directories(new_log_path.parent_path(), err);
        if (err != std::errc()) {
            throw fmt::system_error(
                err.value(),
                "failed to create log directory '{}'",
                new_log_path.parent_path().native()
            );
        }
    }
    init.open(new_log_path, std::ios::app);
    if (! init) {
        throw fmt::system_error(
            errno,
            "failed to open log file '{}'",
            new_log_path.native()
        );
    }
    if (not backtrace_contents.empty()) {
        fmt::print(init, "{}", backtrace_contents);
        init.flush();
    }
    backtrace.pubseekoff(0, std::ios::beg);
}

void Log::set_level(Level const lvl) {
    log_lvl = lvl;
}

void Log::set_common_log(std::filesystem::path const& path) {
    set_log(
        common_log,
        common_log_path,
        path,
        common_log_file_buf,
        common_log_backtrace,
        common_log_mtx
    );
}

void Log::set_domain_log(std::filesystem::path const& path) {
    set_log(
        domain_log,
        domain_log_path,
        path,
        domain_log_file_buf,
        domain_log_backtrace,
        domain_log_mtx
    );
}

void Log::flush_on(Level const lvl) {
    flush_lvl = lvl;
}

void Log::info(std::string_view const what) {
    dispatch_info(false, what);
}

void Log::domain_info(std::string_view const what) {
    dispatch_info(true, what);
}

void Log::started(
    in_port_t const port,
    std::chrono::milliseconds const timeout,
    bool const verbose
) {
    if (log_lvl <= Log::Level::INFO) {
        log(common_log,
            common_log_mtx,
            "[ST - started]",
            bold_green,
            "127.0.0.1:{}; timeout: {}; mode: {}.",
            port,
            timeout,
            verbose ? DEBUG : SHY);
    }
}

void Log::stopped(std::string_view const reason) {
    dispatch_stop(true, reason);
}

void Log::aborted(std::string_view const reason) {
    dispatch_stop(false, reason);
}

void Log::query_sent(Query const& query, HostSockAddr const dest) {
    if (log_lvl <= Log::Level::INFO) {
        log(domain_log,
            domain_log_mtx,
            "[QS - query sent]",
            bold_white,
            "destination: {}; query={}.",
            dest,
            query);
    }
}

void Log::query_received(Query const& query, HostSockAddr const src) {
    if (log_lvl <= Log::Level::INFO) {
        log(domain_log,
            domain_log_mtx,
            "[QR - query received]",
            bold_white,
            "source: {}; query: {}.",
            src,
            query);
    }
}

void Log::response_sent(Query const& response, HostSockAddr const dest) {
    if (log_lvl <= Log::Level::INFO) {
        log(domain_log,
            domain_log_mtx,
            "[RS - response sent]",
            bold_white,
            "destination: {}; response: {}.",
            dest,
            response);
    }
}

void Log::response_received(Query const& response, HostSockAddr const src) {
    if (log_lvl <= Log::Level::INFO) {
        log(domain_log,
            domain_log_mtx,
            "[RR - response received]",
            bold_white,
            "source: {}; response: {}.",
            src,
            response);
    }
}

void Log::zone_transfer_complete(
    bool const primary_server,
    HostSockAddr const peer,
    std::chrono::milliseconds const duration,
    size_t const bytes_transferred
) {
    if (log_lvl <= Log::Level::INFO) {
        log(domain_log,
            domain_log_mtx,
            "[ZT - zone transfer complete]",
            bold_white,
            "self role: {}; peer: {}; duration: {} bytes_transferred: {}.",
            primary_server ? SP : SS,
            peer,
            duration,
            bytes_transferred);
    }
}

void Log::time_out(std::string_view const reason, HostSockAddr const peer) {
    if (log_lvl <= Log::Level::WARN) {
        log(domain_log,
            domain_log_mtx,
            "[TO - timeout]",
            bold_orange,
            "{} {}.",
            reason,
            peer);
    }
}

void Log::encode_error(
    Query const& query,
    std::string_view const reason,
    HostSockAddr const dest
) {
    if (log_lvl <= Log::Level::ERROR) {
        log(domain_log,
            domain_log_mtx,
            "[ER - encode_error]",
            bold_red,
            "{}; destination: {}; query: {}.",
            reason,
            dest,
            query);
    }
}

void Log::decode_error(std::string_view const reason, HostSockAddr const src) {
    if (log_lvl <= Log::Level::ERROR) {
        log(domain_log,
            domain_log_mtx,
            "[ER - decode_error]",
            bold_red,
            "{}; peer: {}.",
            reason,
            src);
    }
}

void Log::zone_transfer_error(
    bool const primary_server,
    HostSockAddr const peer
) {
    if (log_lvl <= Log::Level::ERROR) {
        log(domain_log,
            domain_log_mtx,
            "[EZ - zone_transfer error]",
            bold_red,
            "self role: {}; peer: {}.",
            primary_server ? SP : SS,
            peer);
    }
}

void Log::error(std::string_view const what) {
    dispatch_error(false, what);
}

void Log::domain_error(std::string_view const what) {
    dispatch_error(true, what);
}

void Log::fatal_error(std::string_view const what) {
    if (log_lvl <= Log::Level::FATAL) {
        log(common_log,
            common_log_mtx,
            "[FL - fatal error]",
            bold_red,
            "127.0.0.1 {}.",
            what);
    }
}

static void dispatch_stop(bool const good, std::string_view const reason) {
    if (log_lvl <= Log::Level::INFO) {
        if (good) {
            log(common_log,
                common_log_mtx,
                "[SP - stopped]",
                bold_green,
                "127.0.0.1 {}.",
                reason);
        } else {
            log(common_log,
                common_log_mtx,
                "[SP - stopped]",
                bold_red,
                "127.0.0.1 {}.",
                reason);
        }
    }
}

static void
dispatch_info(bool const domain_specific, std::string_view const what) {
    if (log_lvl <= Log::Level::INFO) {
        if (domain_specific) {
            log(domain_log,
                domain_log_mtx,
                "[EV - info]",
                bold_green,
                "127.0.0.1 {}.",
                what);
        } else {
            log(common_log,
                common_log_mtx,
                "[EV - info]",
                bold_green,
                "127.0.0.1 {}.",
                what);
        }
    }
}

static void
dispatch_error(bool const domain_specific, std::string_view const what) {
    if (log_lvl <= Log::Level::ERROR) {
        if (domain_specific) {
            log(domain_log,
                domain_log_mtx,
                "[EE - error]",
                bold_red,
                "127.0.0.1 {}.",
                what);
        } else {
            log(common_log,
                common_log_mtx,
                "[EE - error]",
                bold_red,
                "127.0.0.1 {}.",
                what);
        }
    }
}

} // namespace minidns

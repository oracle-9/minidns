#include "server/root_servers_database.hpp"

#include "server/parse_error.hpp"

#include <cerrno>
#include <fmt/format.h>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>

namespace minidns {

static constexpr std::string_view ENTRY_COMMENT_START = "#";

RootServersDatabase::RootServersDatabase() noexcept = default;

RootServersDatabase
RootServersDatabase::from_file(std::filesystem::path&& root_servers_db_path) {
    auto root_servers_db_file = std::ifstream(root_servers_db_path);
    if (! root_servers_db_file) {
        throw fmt::system_error(
            errno,
            "failed to open configuration file '{}'",
            std::move(root_servers_db_path).native()
        );
    }

    RootServersDatabase root_servers_db;
    root_servers_db.m_path = std::move(root_servers_db_path);

    LineNum line_num = 0;
    std::string line;
    while (std::getline(root_servers_db_file, line)) {
        ++line_num;
        if (line.empty() or line.starts_with(ENTRY_COMMENT_START)) {
            continue;
        }
        try {
            root_servers_db.m_servers.push_back(HostSockAddr::from_str(line));
        } catch (std::invalid_argument const& err) {
            throw ParseError(
                std::move(root_servers_db.m_path),
                line_num,
                "{}",
                err.what()
            );
        }
    }

    return root_servers_db;
}

std::filesystem::path const& RootServersDatabase::path() const noexcept {
    return m_path;
}

std::span<HostSockAddr const> RootServersDatabase::get() const noexcept {
    return m_servers;
}

} // namespace minidns

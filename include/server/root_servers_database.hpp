#pragma once

#include "shared/sock_addr.hpp"

#include <filesystem>
#include <span>
#include <vector>

namespace minidns {

class RootServersDatabase final {
  private:
    std::filesystem::path m_path;
    std::vector<HostSockAddr> m_servers;

    RootServersDatabase() noexcept;

  public:
    static RootServersDatabase
    from_file(std::filesystem::path&& root_servers_db_path);

    std::filesystem::path const& path() const noexcept;

    std::span<HostSockAddr const> get() const noexcept;
};

} // namespace minidns

#pragma once

#include <cstdint>
#include <exception>
#include <filesystem>
#include <fmt/format.h>
#include <iterator>
#include <string>
#include <utility>

namespace minidns {

using LineNum = std::uint_least32_t;

class ParseError final : public std::exception {
  private:
    std::string msg;

  public:
    template <typename... Args>
    ParseError(
        std::filesystem::path&& filename,
        fmt::format_string<Args...> fmt_str,
        Args&&... args
    )
      : msg(fmt::format(
          "failed to parse file '{}': ",
          std::move(filename).native()
      )) {
        fmt::format_to(
            std::back_inserter(this->msg),
            fmt_str,
            std::forward<Args>(args)...
        );
    }

    template <typename... Args>
    ParseError(
        std::filesystem::path&& filename,
        LineNum const line_num,
        fmt::format_string<Args...> fmt_str,
        Args&&... args
    )
      : msg(fmt::format(
          "failed to parse file '{}', line {}: ",
          std::move(filename).native(),
          line_num
      )) {
        fmt::format_to(
            std::back_inserter(this->msg),
            fmt_str,
            std::forward<Args>(args)...
        );
    }

    char const* what() const noexcept override;
};

} // namespace minidns

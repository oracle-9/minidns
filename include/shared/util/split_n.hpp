#pragma once

#include <array>
#include <cstddef>
#include <string_view>

template <std::size_t N>
constexpr std::array<std::string_view, N>
split_n(std::string_view str, char const delim = ' ') noexcept {
    if constexpr (N == 0) {
        return {};
    }
    std::array<std::string_view, N> tokens;
    std::size_t i = 0;
    while (i < N - 1) {
        std::size_t const delim_pos = str.find(delim);
        if (delim_pos == std::string_view::npos) {
            break;
        }
        tokens[i] = str.substr(0, delim_pos);
        str.remove_prefix(delim_pos + 1);
        ++i;
    }
    tokens[i] = str;
    return tokens;
}

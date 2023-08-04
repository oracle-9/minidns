#pragma once

#include <type_traits>

template <typename Enum>
constexpr auto to_underlying(Enum const value) noexcept {
    return static_cast<std::underlying_type_t<Enum>>(value);
}

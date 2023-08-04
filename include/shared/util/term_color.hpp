#pragma once

#include <fmt/color.h>

#undef bold_white
#define bold_white(str)                                                        \
    fmt::styled(str, fmt::emphasis::bold | fmt::fg(fmt::color::white))

#undef bold_green
#define bold_green(str)                                                        \
    fmt::styled(str, fmt::emphasis::bold | fmt::fg(fmt::color::green))

#undef bold_red
#define bold_red(str)                                                          \
    fmt::styled(str, fmt::emphasis::bold | fmt::fg(fmt::color::red))

#undef bold_orange
#define bold_orange(str)                                                       \
    fmt::styled(str, fmt::emphasis::bold | fmt::fg(fmt::color::orange))

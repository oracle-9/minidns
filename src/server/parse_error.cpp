#include "server/parse_error.hpp"

namespace minidns {

char const* ParseError::what() const noexcept {
    return this->msg.c_str();
}

} // namespace minidns

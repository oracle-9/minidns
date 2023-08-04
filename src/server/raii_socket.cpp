#include "server/raii_socket.hpp"

#include "server/log.hpp"
#include "shared/util/strerror_mt.hpp"

#include <cerrno>
#include <fmt/format.h>

extern "C" {
#include <cerrno>
#include <unistd.h>
}

namespace minidns {

static void try_close(int sock) noexcept;

RAIISocket::RAIISocket(int const sock) noexcept : sock(sock) {}

RAIISocket::RAIISocket(RAIISocket&& other) noexcept : sock(other.sock) {
    other.sock = -1;
}

RAIISocket& RAIISocket::operator=(RAIISocket&& other) noexcept {
    try_close(this->sock);
    this->sock = other.sock;
    other.sock = -1;
    return *this;
}

RAIISocket::~RAIISocket() {
    try_close(this->sock);
}

RAIISocket RAIISocket::from_native(int const sock) noexcept {
    return RAIISocket(sock);
}

bool RAIISocket::operator!() const noexcept {
    return this->sock == -1;
}

int RAIISocket::get() const {
    return this->sock;
}

static void try_close(int const sock) noexcept {
    try {
        if (close(sock) == -1) {
            Log::error(fmt::format(
                "failed to close socket {}: {}",
                sock,
                strerror_mt(errno)
            ));
        }
    } catch (...) {
        // Ignore e.g. possible exceptions from Log::error()/fmt::format().
    }
}

} // namespace minidns

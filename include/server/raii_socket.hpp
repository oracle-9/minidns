#pragma once

namespace minidns {

class RAIISocket {
  private:
    int sock;
    explicit RAIISocket(int sock) noexcept;

  public:
    // Not copy/default.
    RAIISocket() = delete;
    RAIISocket(RAIISocket const&) = delete;
    RAIISocket& operator=(RAIISocket const&) = delete;

    // Only move.
    RAIISocket(RAIISocket&& other) noexcept;
    RAIISocket& operator=(RAIISocket&& other) noexcept;

    ~RAIISocket();

    static RAIISocket from_native(int sock) noexcept;

    bool operator!() const noexcept;

    int get() const;
};

} // namespace minidns

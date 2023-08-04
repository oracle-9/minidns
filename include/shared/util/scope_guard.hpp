#pragma once

#include <concepts>
#include <utility>

template <std::invocable F>
class ScopeGuard final {
  private:
    F f;

  public:
    template <typename... Args>
        requires std::constructible_from<F, Args...>
    explicit(false) ScopeGuard(Args&&... args)
      : f(std::forward<Args>(args)...) {}

    ScopeGuard() = delete;
    ScopeGuard(ScopeGuard const&) = delete;
    ScopeGuard(ScopeGuard&&) = delete;
    ScopeGuard& operator=(ScopeGuard const&) = delete;
    ScopeGuard& operator=(ScopeGuard&&) = delete;

    ~ScopeGuard() {
        try {
            f();
        } catch (...) {}
    }
};

template <typename F>
ScopeGuard(F&&) -> ScopeGuard<F>;

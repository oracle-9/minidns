#include "shared/util/strerror_mt.hpp"

#include <array>
#include <cstring>

char const* strerror_mt(int const errnum) noexcept {
    static thread_local char buf[256];
    return strerror_r(errnum, buf, std::size(buf))
#if _POSIX_C_SOURCE >= 200112L and not _GNU_SOURCE
           // POSIX version of strerror_r returns an int.
           ,
           buf
#endif
        ;
}

# ###############################################################################
# Header
# ###############################################################################
cmake_minimum_required(VERSION 3.22)
project("minidns" VERSION 1.0 LANGUAGES CXX)

# ###############################################################################
# Options
# ###############################################################################
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ###############################################################################

# ###############################################################################
# Paths
# ###############################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set(SRC_PATH "${PROJECT_SOURCE_DIR}/src")
set(INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include")

# ###############################################################################

# ###############################################################################
# Targets
# ###############################################################################
# minidns
file(GLOB_RECURSE MINDNS_HEADERS CONFIGURE_DEPENDS
    "${INCLUDE_PATH}/client/*.hpp"
    "${INCLUDE_PATH}/shared/*.hpp"
)

file(GLOB_RECURSE MINDNS_SOURCES CONFIGURE_DEPENDS
    "${SRC_PATH}/client/*.cpp"
    "${SRC_PATH}/shared/*.cpp"
)

add_executable(minidns ${MINDNS_HEADERS} ${MINDNS_SOURCES})
target_include_directories(minidns PRIVATE ${INCLUDE_PATH})

# minidnsd
file(GLOB_RECURSE MINDNSD_HEADERS CONFIGURE_DEPENDS
    "${INCLUDE_PATH}/server/*.hpp"
    "${INCLUDE_PATH}/shared/*.hpp"
)

file(GLOB_RECURSE MINDNSD_SOURCES CONFIGURE_DEPENDS
    "${SRC_PATH}/server/*.cpp"
    "${SRC_PATH}/shared/*.cpp"
)

add_executable(minidnsd ${MINDNSD_HEADERS} ${MINDNSD_SOURCES})
target_include_directories(minidnsd PRIVATE ${INCLUDE_PATH})

# ###############################################################################

# ###############################################################################
# 3rd Party Libraries
# ###############################################################################
# minidns
# fmt
find_package(fmt CONFIG REQUIRED)
target_link_libraries(minidns PRIVATE fmt::fmt)

# cxxopts
find_package(cxxopts CONFIG REQUIRED)
target_link_libraries(minidns PRIVATE cxxopts::cxxopts)

# spdlog
find_package(spdlog CONFIG REQUIRED)
target_link_libraries(minidns PRIVATE spdlog::spdlog)

# minidnsd
# fmt
find_package(fmt CONFIG REQUIRED)
target_link_libraries(minidnsd PRIVATE fmt::fmt)

# cxxopts
find_package(cxxopts CONFIG REQUIRED)
target_link_libraries(minidnsd PRIVATE cxxopts::cxxopts)

# ###############################################################################

# ###############################################################################
# Precompiled headers
# ###############################################################################
# minidns
target_precompile_headers(minidns PRIVATE
    "${INCLUDE_PATH}/shared/util/scope_guard.hpp"
    "${INCLUDE_PATH}/shared/util/split_n.hpp"
    "${INCLUDE_PATH}/shared/util/strerror_mt.hpp"
    "${INCLUDE_PATH}/shared/util/term_color.hpp"
    "${INCLUDE_PATH}/shared/util/to_underlying.hpp"
    "<algorithm>"
    "<arpa/inet.h>"
    "<array>"
    "<cerrno>"
    "<charconv>"
    "<climits>"
    "<concepts>"
    "<cstddef>"
    "<cstdint>"
    "<cstdio>"
    "<cstdlib>"
    "<cstring>"
    "<cxxopts.hpp>"
    "<exception>"
    "<fmt/color.h>"
    "<fmt/core.h>"
    "<fmt/format.h>"
    "<functional>"
    "<iostream>"
    "<netinet/in.h>"
    "<span>"
    "<spdlog/spdlog.h>"
    "<stdexcept>"
    "<string>"
    "<string_view>"
    "<sys/socket.h>"
    "<sys/time.h>"
    "<sys/types.h>"
    "<system_error>"
    "<type_traits>"
    "<unistd.h>"
    "<utility>"
    "<variant>"
)

# minidnsd
target_precompile_headers(minidnsd PRIVATE
    "${INCLUDE_PATH}/shared/util/scope_guard.hpp"
    "${INCLUDE_PATH}/shared/util/split_n.hpp"
    "${INCLUDE_PATH}/shared/util/strerror_mt.hpp"
    "${INCLUDE_PATH}/shared/util/term_color.hpp"
    "${INCLUDE_PATH}/shared/util/to_underlying.hpp"
    "<any>"
    "<algorithm>"
    "<arpa/inet.h>"
    "<array>"
    "<cerrno>"
    "<charconv>"
    "<chrono>"
    "<climits>"
    "<concepts>"
    "<csignal>"
    "<cstddef>"
    "<cstdint>"
    "<cstdio>"
    "<cstdlib>"
    "<cstring>"
    "<cxxopts.hpp>"
    "<exception>"
    "<filesystem>"
    "<fmt/chrono.h>"
    "<fmt/color.h>"
    "<fmt/core.h>"
    "<fmt/format.h>"
    "<functional>"
    "<iostream>"
    "<netinet/in.h>"
    "<span>"
    "<stdexcept>"
    "<string>"
    "<string_view>"
    "<sys/socket.h>"
    "<sys/time.h>"
    "<sys/types.h>"
    "<system_error>"
    "<type_traits>"
    "<unistd.h>"
    "<utility>"
    "<variant>"
)

# ###############################################################################
# CCache
# ###############################################################################
find_program(CCACHE_FOUND ccache)

if(CCACHE_FOUND)
    message(STATUS "ccache found: ${MOLD_EXECUTABLE}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

# ###############################################################################

# ###############################################################################
# Compiler flags
# ###############################################################################
if(MSVC)
    # Compiling with Microsoft Visual C++.
    list(APPEND WARNING_FLAGS "/W4")
else()
    # Compiling with g++/clang++/etc.
    list(
        APPEND WARNING_FLAGS
        "-pedantic-errors"
        "-Wfatal-errors"
        "-Werror=pedantic"
        "-Wall"
        "-Wextra"
        "-Wdouble-promotion"
        "-Wconversion"
        "-Wsign-conversion"
    )
endif()

target_compile_options(minidns PRIVATE ${WARNING_FLAGS})
target_compile_options(minidnsd PRIVATE ${WARNING_FLAGS})

# ###############################################################################

# ###############################################################################
# Mold Linker
# ###############################################################################
find_program(MOLD_EXECUTABLE "mold")

if(MOLD_EXECUTABLE)
    message(STATUS "mold linker found: ${MOLD_EXECUTABLE}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=mold")
else()
    message(STATUS "mold linker not found.")
endif()

# ###############################################################################

# ###############################################################################
# Linker Flags
# ###############################################################################
set_target_properties(minidns PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(minidnsd PROPERTIES LINK_FLAGS_RELEASE -s)
message(STATUS "Release build binary striping enabled.")

# ###############################################################################

# ###############################################################################
# Link-Time-Optimization
# ###############################################################################
include(CheckIPOSupported)

check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT USE_LTO_ERROR)

if(LTO_SUPPORTED)
    message(STATUS "LTO enabled")
    set_property(TARGET minidns PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET minidnsd PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "LTO not supported")
endif()

# ###############################################################################

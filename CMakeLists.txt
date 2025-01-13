cmake_minimum_required(VERSION 3.20)
project(flowgen_dpdk C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK REQUIRED libdpdk)

add_executable(flowgen_dpdk main.c)

# Use the following for SHARED linking
target_compile_options(flowgen_dpdk PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(flowgen_dpdk ${LIBDPDK_LDFLAGS})
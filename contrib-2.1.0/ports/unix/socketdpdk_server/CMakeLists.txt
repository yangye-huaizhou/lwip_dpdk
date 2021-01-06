cmake_minimum_required(VERSION 3.8)

project(socket_server C)

set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LWIP_CONTRIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(LWIP_DIR         ${CMAKE_CURRENT_SOURCE_DIR}/../../../../lwip)
set(RTE_SDK          /home/yangye/vhost-user/dpdk-stable-17.11.9)
set(RTE_TARGET       x86_64-native-linuxapp-gcc)

include(${LWIP_CONTRIB_DIR}/ports/CMakeCommon.cmake)

set (LWIP_DEFINITIONS -DLWIP_DEBUG)
set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${LWIP_CONTRIB_DIR}/ports/unix/socketdpdk_server"
)

set (DPDK_INCLUDE_DIRS "${RTE_SDK}/${RTE_TARGET}/include")
set (DPDK_LIB_DIRS "${RTE_SDK}/${RTE_TARGET}/lib")

include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/Filelists.cmake)
include(${LWIP_DIR}/src/Filelists.cmake)

add_executable(socker_server ${LWIP_CONTRIB_DIR}/ports/unix/socketdpdk_server/socket_server.c ${LWIP_CONTRIB_DIR}/ports/unix/socketdpdk_server/dpdk.c)
target_include_directories(socker_server PRIVATE ${LWIP_INCLUDE_DIRS} ${DPDK_INCLUDE_DIRS})
target_compile_options(socker_server PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(socker_server PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(socker_server ${LWIP_SANITIZER_LIBS} lwipcontribportunix lwipcore "-L${DPDK_LIB_DIRS}" "-Wl,--whole-archive" rte_mempool_octeontx rte_pci rte_kvargs rte_ethdev rte_bus_pci rte_bus_vdev rte_eal rte_mempool rte_mempool_ring rte_ring rte_mbuf rte_pmd_ixgbe rte_hash "-Wl,--no-whole-archive" numa dl)
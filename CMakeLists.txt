cmake_minimum_required(VERSION 3.16)

project(ElectricMoneyV20_7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(Boost REQUIRED)

if(WIN32)
    find_package(json-c CONFIG REQUIRED)
    set(EM_JSONC_TARGET json-c::json-c)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JSONC REQUIRED IMPORTED_TARGET json-c)
    set(EM_JSONC_TARGET PkgConfig::JSONC)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(EM_MODULES
    src/common.cpp
    src/wallet.cpp
    src/transaction.cpp
    src/mining.cpp
    src/block.cpp
    src/blockchain.cpp
    src/l2.cpp
    src/network.cpp
    src/bridge.cpp
    src/app.cpp
)

add_library(em_modules STATIC ${EM_MODULES})

target_include_directories(
    em_modules
    PUBLIC
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(
    em_modules
    PUBLIC
    OpenSSL::Crypto
    ${EM_JSONC_TARGET}
)

if(WIN32)
    target_link_libraries(
        em_modules
        PUBLIC
        ws2_32
    )
endif()

if(MSVC)
    target_compile_options(
        em_modules
        PRIVATE
        /W4
        /permissive-
    )
else()
    target_compile_options(
        em_modules
        PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

add_executable(electric_money src/main.cpp)

target_link_libraries(
    electric_money
    PRIVATE
    em_modules
)

add_executable(em_tests tests/test_self.cpp)

target_link_libraries(
    em_tests
    PRIVATE
    em_modules
)

enable_testing()

add_test(
    NAME em_self_test
    COMMAND em_tests
)

add_executable(em_hardening tests/hardening.cpp)

target_link_libraries(
    em_hardening
    PRIVATE
    em_modules
)

add_test(
    NAME em_hardening
    COMMAND em_hardening
)

add_executable(em_consensus_vectors tests/consensus_vectors.cpp)

target_link_libraries(
    em_consensus_vectors
    PRIVATE
    em_modules
)

add_test(
    NAME em_consensus_vectors
    COMMAND em_consensus_vectors
)

add_executable(em_consensus_transition tests/consensus_transition.cpp)

target_link_libraries(
    em_consensus_transition
    PRIVATE
    em_modules
)

add_test(
    NAME em_consensus_transition
    COMMAND em_consensus_transition
)

add_executable(em_l2_bridge_gate tests/l2_bridge_gate.cpp)

target_link_libraries(
    em_l2_bridge_gate
    PRIVATE
    em_modules
)

add_test(
    NAME em_l2_bridge_gate
    COMMAND em_l2_bridge_gate
)

#pragma once

#include "common.hpp"

class Wallet {
    EVP_PKEY*pkey=nullptr;
    public:
    static constexpr size_t PUB_HEX=MLDSA65_PUBLIC_KEY_BYTES*2;
    static constexpr size_t SIG_HEX=MLDSA65_SIGNATURE_BYTES*2;
    std::string public_key_hex,address;Wallet();
~Wallet();

    Wallet(const Wallet&)=delete;
    Wallet&operator=(const Wallet&)=delete;std::string sign(const std::string&msg)const;
static bool verify(const std::string&pubhex,const std::string&msg,const std::string&sighex);

};

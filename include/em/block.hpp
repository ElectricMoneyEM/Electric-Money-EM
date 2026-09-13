#pragma once

#include "common.hpp"
#include "transaction.hpp"
#include "mining.hpp"

struct Block {
    int index=0;
    std::string previous_hash,merkle_root,extra_data,block_hash;
    std::vector<std::string>transactions;
    i64 timestamp=0;
    u64 nonce=0;
    int difficulty=1;std::string header_json()const;
std::string calc_hash()const;

    void mine(const std::function<bool()>&stop=[](){ return false; });
std::string json()const;

};
std::string merkle(const std::vector<std::string>&items);

bool parse_block(const std::string&s,Block&b);

std::string chain_json(const std::vector<Block>&c);

bool parse_chain(const std::string&s,std::vector<Block>&out);



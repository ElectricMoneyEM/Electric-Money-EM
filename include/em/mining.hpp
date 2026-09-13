#pragma once

#include "common.hpp"

struct MiningShare {
    std::string miner,job_id,share_hash,share_id;
    int difficulty=1;
    u64 nonce=0;static std::string challenge(const std::string&job,int d);
std::string calc_hash()const;
std::string calc_id()const;
bool valid(const std::string&job,int d)const;
std::string json()const;

};
i64 subsidy(int h);

cpp_int block_work(int d);


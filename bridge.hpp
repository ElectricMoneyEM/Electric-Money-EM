#pragma once

#include "common.hpp"
#include "transaction.hpp"
#include "wallet.hpp"
#include "l2.hpp"
std::string withdrawal_release_id_fields(const std::string&commitment_hash,const std::string&recipient,const std::string&claim,i64 amount);

std::string withdrawal_release_id(const std::string&commitment_hash,const L2Withdrawal&w);

std::string make_l2_withdrawal_release(const std::string&commitment_hash,const L2Withdrawal&w);

Transaction make_transfer(const Wallet&w,const std::string&to,i64 em,i64 nonce);

MiningShare make_share(const std::string&m,const std::string&job,int d,u64 n);


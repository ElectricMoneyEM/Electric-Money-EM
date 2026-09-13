#pragma once

#include "common.hpp"
#include "wallet.hpp"

struct Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;std::string sender()const;
i64 burned()const;
i64 receiver_tax()const;
i64 net_amount()const;
std::string signing_json()const;
std::string id_json()const;
bool valid(i64 now=now_s(),bool age=true)const;
std::string json()const;

};

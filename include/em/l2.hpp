#pragma once

#include "common.hpp"
#include "transaction.hpp"
#include "wallet.hpp"
#include "block.hpp"

struct L2Deposit {
    std::string l1_tx_id, l1_block_hash, l2_recipient, claim_id; i64 amount=0;std::string json() const;

};
struct L2Withdrawal {
    std::string l2_tx_id, l2_recipient, claim_id; i64 amount=0;std::string json() const;

};
std::string bridge_claim_id(const L2Deposit&d);

std::string withdrawal_claim_id(const L2Withdrawal&w);

bool parse_l2_deposit(json_object*o,L2Deposit&d);

bool parse_l2_withdrawal(json_object*o,L2Withdrawal&w);

struct L2Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;std::string signing()const;
bool valid()const;
std::string json()const;

};
std::string l2_state_root(const std::map<std::string,i64>&balances,const std::map<std::string,i64>&nonces);

bool parse_l2_map(json_object*o,const char*key,std::map<std::string,i64>&out);

bool parse_l2_tx(json_object*v,L2Transaction&t);

std::string l2_state_root(const std::map<std::string,i64>&balances,const std::map<std::string,i64>&nonces);
std::string last_l2_state_root(const std::vector<Block>&prefix);

bool commitment_has_withdrawal(json_object*commit,const std::string&claim_id,const std::string&recipient,i64 amount);

bool prior_release_exists(const std::vector<Block>&prefix,const std::string&claim_id);

bool find_finalized_withdrawal(const std::vector<Block>&prefix,const std::string&commitment_hash,const std::string&claim_id,const std::string&recipient,i64 amount);

bool find_finalized_deposit(const std::vector<Block>&prefix,const L2Deposit&d);

bool verify_l2_deposit_manifest(json_object*o,const std::vector<Block>&prefix);

bool verify_l2_commitment(json_object*o,const std::string&expected_prev_root);

class Layer2Sequencer {
    public:
    std::map<std::string,i64>balances,nonces;
    std::vector<L2Transaction>mempool;
    u64 sequence=0;
    std::string poh=sha3_512("EM_L2_POH_GENESIS");
    std::vector<std::string>commitments;
    std::vector<L2Deposit> batch_deposits;
    std::vector<L2Withdrawal> batch_withdrawals;
    std::set<std::string> spent_deposit_claims, spent_withdrawal_claims;
    std::map<std::string,i64>batch_pre_balances,batch_pre_nonces;
    std::string batch_pre_poh; u64 batch_first_sequence=0;bool deposit(const std::string&a,i64 x);
bool claim_l1_deposit(const L2Deposit&d,const std::vector<Block>&l1_chain);
bool request_withdrawal(const std::string&recipient,i64 x);
bool add(const L2Transaction&t);
std::optional<std::string>commit();

};

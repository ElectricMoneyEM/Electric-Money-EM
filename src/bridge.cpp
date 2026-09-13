#include "em/bridge.hpp"

std::string withdrawal_release_id_fields(const std::string&commitment_hash,const std::string&recipient,const std::string&claim,i64 amount) { return sha3_512(canonical({{"amount",std::to_string(amount)}, {"claim_id",json_escape(claim)}, {"commitment_hash",json_escape(commitment_hash)}, {"recipient",json_escape(recipient)}, {"type",json_escape("l2_withdrawal_release")}})); }

std::string withdrawal_release_id(const std::string&commitment_hash,const L2Withdrawal&w) { return withdrawal_release_id_fields(commitment_hash,w.l2_recipient,w.claim_id,w.amount); }

std::string make_l2_withdrawal_release(const std::string&commitment_hash,const L2Withdrawal&w) {
    if(!is_hex(commitment_hash,128)||!is_hex(w.l2_recipient,128)||!is_hex(w.claim_id,128)||w.amount<=0||w.amount>MAX_SUPPLY||w.claim_id!=withdrawal_claim_id(w)) throw std::runtime_error("invalid L2 withdrawal release");
    return canonical({{"amount",std::to_string(w.amount)}, {"claim_id",json_escape(w.claim_id)}, {"commitment_hash",json_escape(commitment_hash)}, {"recipient",json_escape(w.l2_recipient)}, {"tx_id",json_escape(withdrawal_release_id(commitment_hash,w))}, {"type",json_escape("l2_withdrawal_release")}});
}

Transaction make_transfer(const Wallet&w,const std::string&to,i64 em,i64 nonce) {
    if(em<=0 || em>MAX_TX_AMOUNT/COIN) throw std::runtime_error("EM amount overflow/out of range");
    if(nonce<0) throw std::runtime_error("negative nonce");
    checked_amount(em*COIN);
    Transaction t;
    t.sender_pubkey=w.public_key_hex;
    t.recipient=to;
    t.amount=em*COIN;
    t.nonce=nonce;
    t.timestamp=now_s();
    t.signature=w.sign(t.signing_json());
    t.tx_id=hash_obj( {
         {
            "amount",std::to_string(t.amount)
        }
        , {
            "nonce",std::to_string(t.nonce)
        }
        , {
            "recipient",json_escape(t.recipient)
        }
        , {
            "sender_pubkey",json_escape(t.sender_pubkey)
        }
        , {
            "signature",json_escape(t.signature)
        }
        , {
            "timestamp",std::to_string(t.timestamp)
        }
    }
    );
    return t;
}

MiningShare make_share(const std::string&m,const std::string&job,int d,u64 n) {
    MiningShare s;
    s.miner=m;
    s.job_id=job;
    s.difficulty=d;
    s.nonce=n;
    s.share_hash=s.calc_hash();
    s.share_id=s.calc_id();
    return s;
}


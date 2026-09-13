#include "em/transaction.hpp"

std::string Transaction::sender()const {
        return sha3_512(std::string((char*)unhex(sender_pubkey).data(),unhex(sender_pubkey).size()));
    }

i64 Transaction::burned()const {
        return (amount*TX_BURN_BPS)/10000;
    }

i64 Transaction::receiver_tax()const {
        return (amount*RECEIVER_TAX_BPS)/10000;
    }

i64 Transaction::net_amount()const {
        return amount-receiver_tax()-burned();
    }

std::string Transaction::signing_json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }

std::string Transaction::id_json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }

bool Transaction::valid(i64 now,bool age)const {
        if(amount<=0||amount>MAX_TX_AMOUNT||nonce<0||!is_hex(sender_pubkey,Wallet::PUB_HEX)||!is_hex(recipient,128)||recipient=="SYSTEM"||signature.empty()||!is_hex(signature,Wallet::SIG_HEX))return false;
        if(age&&(timestamp<now-MAX_TX_AGE||timestamp>now+MAX_FUTURE_BLOCK_TIME))return false;
        return tx_id==hash_obj( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        )&&Wallet::verify(sender_pubkey,signing_json(),signature);
    }

std::string Transaction::json()const {
        return canonical( {
             {
                "amount",std::to_string(amount)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "recipient",json_escape(recipient)
            }
            , {
                "sender_pubkey",json_escape(sender_pubkey)
            }
            , {
                "signature",json_escape(signature)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
            , {
                "tx_id",json_escape(tx_id)
            }
        }
        );
    }


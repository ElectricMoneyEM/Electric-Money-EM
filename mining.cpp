#include "em/mining.hpp"

std::string MiningShare::challenge(const std::string&job,int d) {
        return sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+job+"-"+std::to_string(d));
    }

std::string MiningShare::calc_hash()const {
        return sha3_512(challenge(job_id,difficulty)+miner+std::to_string(nonce));
    }

std::string MiningShare::calc_id()const {
        return hash_obj( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "job_id",json_escape(job_id)
            }
            , {
                "miner",json_escape(miner)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "share_hash",json_escape(share_hash)
            }
            , {
                "type",json_escape("mining_share")
            }
        }
        );
    }

bool MiningShare::valid(const std::string&job,int d)const {
        return is_hex(miner,128)&&is_hex(job_id,128)&&difficulty>=1&&job_id==job&&difficulty==d&&share_hash==calc_hash()&&share_hash.rfind(std::string(difficulty,'0'),0)==0&&share_id==calc_id();
    }

std::string MiningShare::json()const {
        return canonical( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "job_id",json_escape(job_id)
            }
            , {
                "miner",json_escape(miner)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "share_hash",json_escape(share_hash)
            }
            , {
                "share_id",json_escape(share_id)
            }
            , {
                "type",json_escape("mining_share")
            }
        }
        );
    }

i64 subsidy(int h) {
    if(h<=0)return BASE_REWARD;
    int halv=h/HALVING_INTERVAL;
    if(halv>=63)return 0;
    return INITIAL_BLOCK_REWARD>>halv;
}

cpp_int block_work(int d) {
    return cpp_int(1) << (4*d);
}


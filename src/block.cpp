#include "em/block.hpp"

std::string Block::header_json()const {
        return canonical( {
             {
                "difficulty",std::to_string(difficulty)
            }
            , {
                "extra_data",json_escape(extra_data)
            }
            , {
                "index",std::to_string(index)
            }
            , {
                "merkle_root",json_escape(merkle_root)
            }
            , {
                "nonce",std::to_string(nonce)
            }
            , {
                "previous_hash",json_escape(previous_hash)
            }
            , {
                "timestamp",std::to_string(timestamp)
            }
        }
        );
    }

std::string Block::calc_hash()const {
        return sha3_512(header_json());
    }

std::string Block::json()const {
        std::ostringstream o;
        o<<"{\"difficulty\":"<<difficulty<<",\"extra_data\":"<<json_escape(extra_data)<<",\"hash\":"<<json_escape(block_hash)<<",\"index\":"<<index<<",\"merkle_root\":"<<json_escape(merkle_root)<<",\"nonce\":"<<nonce<<",\"previous_hash\":"<<json_escape(previous_hash)<<",\"timestamp\":"<<timestamp<<",\"transactions\":[";
        for(size_t i=0;i<transactions.size();++i) {
            if(i)o<<',';
            o<<transactions[i];
        }
        o<<"]}";
        return o.str();
    }

std::string merkle(const std::vector<std::string>&items) {
    if(items.empty())return sha3_512("");
    std::vector<std::string>v=items;
    while(v.size()>1) {
        if(v.size()%2)v.push_back(v.back());
        std::vector<std::string>n;
        for(size_t i=0;i<v.size();i+=2)n.push_back(sha3_512(v[i]+v[i+1]));
        v.swap(n);
    }
    return v[0];
}

bool parse_block(const std::string&s,Block&b) {
    json_tokener*tok=json_tokener_new();
    if(!tok)return false;
    json_object*o=json_tokener_parse_ex(tok,s.data(),static_cast<int>(s.size()));
    bool ok=o && json_tokener_get_error(tok)==json_tokener_success && json_object_is_type(o,json_type_object);
    if(!ok){if(o)json_object_put(o);json_tokener_free(tok);return false;}
    json_object*arr=nullptr;
    ok=json_get_int(o,"index",b.index)&&json_get_string(o,"previous_hash",b.previous_hash)&&
       json_get_string(o,"merkle_root",b.merkle_root)&&json_get_string(o,"extra_data",b.extra_data)&&
       json_get_string(o,"hash",b.block_hash)&&json_get_i64(o,"timestamp",b.timestamp)&&
       json_get_u64(o,"nonce",b.nonce)&&json_get_int(o,"difficulty",b.difficulty)&&
       json_object_object_get_ex(o,"transactions",&arr)&&json_object_is_type(arr,json_type_array);
    if(ok) {
        size_t n=json_object_array_length(arr);
        if(n>static_cast<size_t>(MAX_TX_PER_BLOCK+MAX_SHARES_PER_BLOCK)) ok=false;
        for(size_t i=0;ok&&i<n;++i) {
            json_object*x=json_object_array_get_idx(arr,i);
            if(!x||!json_object_is_type(x,json_type_object)) {ok=false;break;}
            const char*raw=json_object_to_json_string(x);
            if(!raw||std::strlen(raw)>MAX_BLOCK_BYTES) {ok=false;break;}
            b.transactions.emplace_back(raw);
        }
    }
    json_object_put(o); json_tokener_free(tok);
    if(!ok)return false;
    return s.size()<=MAX_BLOCK_BYTES;
}

std::string chain_json(const std::vector<Block>&c) {
    std::ostringstream o; o<<"[";
    for(size_t i=0;i<c.size();++i){ if(i)o<<','; o<<c[i].json(); if(o.tellp()>static_cast<std::streamoff>(MAX_CHAIN_SYNC_BYTES)) return {}; }
    o<<"]"; return o.str();
}

bool parse_chain(const std::string&s,std::vector<Block>&out) {
    if(s.size()>MAX_CHAIN_SYNC_BYTES)return false;
    json_tokener*tok=json_tokener_new(); if(!tok)return false;
    json_object*o=json_tokener_parse_ex(tok,s.data(),static_cast<int>(s.size()));
    bool ok=o&&json_tokener_get_error(tok)==json_tokener_success&&json_object_is_type(o,json_type_array);
    if(!ok){if(o)json_object_put(o);json_tokener_free(tok);return false;}
    size_t n=json_object_array_length(o); if(n==0||n>100000){json_object_put(o);json_tokener_free(tok);return false;}
    out.reserve(n);
    for(size_t i=0;i<n;++i){ Block b; json_object*x=json_object_array_get_idx(o,i); if(!x){ok=false;break;} const char*raw=json_object_to_json_string(x); if(!raw||!parse_block(raw,b)){ok=false;break;} out.push_back(std::move(b)); }
    json_object_put(o); json_tokener_free(tok); return ok;
}


void Block::mine(const std::function<bool()>&stop) {
        for(;;) {
            if(stop())throw std::runtime_error("mining interrupted");
            block_hash=calc_hash();
            if(block_hash.rfind(std::string(difficulty,'0'),0)==0)return;
            ++nonce;
        }
    }

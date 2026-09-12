#include <openssl/params.h>
#include <openssl/core_names.h>
#include <functional>
#include <cctype>
// Electric Money V19.2 Post-Quantum — C++17 consensus/reference port (verifiable L2/PoH bridge foundation)
// Derived from Electric Money V17.3 with stronger persistence, mempool recovery, and V18 protocol separation.
// NOT production/mainnet cryptocurrency software.
// Requires OpenSSL 3.5+ (ML-DSA-65) and json-c.
// Build: g++ -std=c++17 -O2 -pthread electric_money_v19_2.cpp -lcrypto -ljson-c -o electric_money
//
// V18 improvements vs V17.3:
// - Annual wallet tax: at most ONE cycle per wallet per block (DoS fix)
// - Difficulty retarget interval raised from 10 -> 144 blocks (~1 day)
// - Protocol/network identifiers retained for V17 consensus compatibility
// - Safe bounded DB parsing and persistence restoration
// - Exact pending transaction removal
// - Checked treasury distribution
// - O(1) SeenSet eviction
// - Explicit bounded mempool capacity
// - Restart recovery prunes stale/impossible pending transactions
// - Crash-durability barrier for atomic database replacement
// - V18 protocol/network separation to prevent accidental cross-version peers
// V18.1 additions: versioned protocol handshake, bounded P2P server/client, tip sync, block relay, cumulative-work reorg acceptance.
// V19.1 additions: L1-bound L2 deposits, withdrawal intents, replay protection,
// commitment-bound bridge manifests, and deterministic bridge verification.
// V19.2 additions: finalized bridge inputs, consensus-bound L2 withdrawal releases,
// persistent claim/nullifier semantics through chain replay, and L2 event transition proofs.
// V19.2 additions: consensus-bound withdrawal releases, finalized commitment
// checks, persistent release nullifiers, and L2 withdrawal transition proofs.
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <json-c/json.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <deque>
#include <unordered_map>
#include <netdb.h>
#include <signal.h>
#include <boost/multiprecision/cpp_int.hpp>
using i64 = std::int64_t;
using u64 = std::uint64_t;
using boost::multiprecision::cpp_int;
static constexpr i64 COIN=100000000;
static constexpr i64 MAX_SUPPLY=7227002484100600LL;
static constexpr i64 BASE_REWARD=25*COIN;
static constexpr i64 INITIAL_BLOCK_REWARD=25*COIN;
static constexpr int HALVING_INTERVAL=1445400;
static constexpr int TX_BURN_BPS=5;
static constexpr int RECEIVER_TAX_BPS=20;
static constexpr int TARGET_BLOCK_TIME=600;
static constexpr int MONTH_SECONDS=30*24*60*60;
static constexpr int YEAR_SECONDS=365*24*60*60;
static constexpr int MINER_REWARD_EPOCH_BLOCKS=MONTH_SECONDS/TARGET_BLOCK_TIME;
static constexpr int DIFFICULTY_INTERVAL=144;  // V17.1: ~1 day (was 10)
static constexpr int GENESIS_DIFFICULTY=2;
static constexpr int MIN_DIFFICULTY=1;
static constexpr int MAX_DIFFICULTY=32;
static constexpr int MAX_FUTURE_BLOCK_TIME=120;
static constexpr int MAX_TX_AGE=24*60*60;
static constexpr i64 MAX_TX_AMOUNT=MAX_SUPPLY;
static constexpr int MAX_TX_PER_BLOCK=5000;
static constexpr size_t MAX_BLOCK_BYTES=2*1024*1024;
static constexpr int MTP_WINDOW=11;
static constexpr int PROTOCOL_VERSION=19; // V19.2 consensus protocol family
static constexpr int P2P_PROTOCOL_VERSION=2;
static constexpr int L2_PROTOCOL_VERSION=3;
static constexpr int BRIDGE_FINALITY_DEPTH=6;
static constexpr size_t MAX_L2_RELEASES_PER_BLOCK=256;
static constexpr size_t MAX_L2_DEPOSITS_PER_BATCH=256;
static constexpr size_t MAX_L2_WITHDRAWALS_PER_BATCH=256;
static constexpr size_t MAX_L2_TX_PER_BATCH=2048;
static constexpr int P2P_HANDSHAKE_TIMEOUT_SEC=10;
static constexpr int P2P_IDLE_TIMEOUT_SEC=60;
static constexpr size_t MAX_CHAIN_SYNC_BYTES=(16ULL*1024ULL*1024ULL)-4096;
static constexpr int MLDSA65_PUBLIC_KEY_BYTES=1952;
static constexpr int MLDSA65_SIGNATURE_BYTES=3309;
static constexpr size_t MAX_FRAME_BYTES=16*1024*1024;
static constexpr size_t MAX_DB_BYTES=512ULL*1024ULL*1024ULL;
static constexpr size_t MAX_PENDING_TX=100000; // bounded JSON DB parser memory exposure
static constexpr int MAX_ORPHANS=2048;
static constexpr int MAX_PEERS=64;
static constexpr int MINING_SHARE_MIN_DIFFICULTY=1;
static constexpr int SHARE_DIFFICULTY_OFFSET=1;
static constexpr int MAX_SHARES_PER_BLOCK=256;
static constexpr int MAX_PENDING_SHARES=20000;
static constexpr int MAX_TAX_CYCLES_PER_BLOCK=1;  // V17.1: max annual tax cycles per wallet per block
static constexpr int MAX_SEEN=50000;
static const std::string NETWORK_ID="ELECTRIC-MONEY-TESTNET-V19.2-L2-POH-BRIDGE-PQ-1";
static const std::string PQ_ALG="ML-DSA-65";
static const std::string ZERO_HASH(128,'0');
static const std::string L2_BRIDGE_ADDRESS="7823631728560445538ef788b9646133d5fe4c1026fd187cdf4040eac4aea91c5d934f79f9b99223c7bb1d8d4aec71777cadba0017697bf26750347558a81a6d";
static const std::string L2_BRIDGE_LABEL="EM_L2_BRIDGE";
static const std::string TREASURY_ADDRESS="ELECTRIC_MONEY_TREASURY";
static const std::string GENESIS_HASH="00c5997a54747344d26e5f375e1cb95c2298c046003d85473e30486c2ac5cd0f630c8e31f0c64c8224401bbc9bef04cb91ab8a08d227d4d46c0bc2d844c8c4f0";
static const std::string GENESIS_MERKLE="befa9c9f23413acb76d5c7fe6dd70967293f0f60f5c87f5a849d077bbf05338b901d213003930b1b4f988a9cd2eff1da81859e52fadac3f53b20438f269c609b";
static constexpr u64 GENESIS_NONCE=372;
static const std::string GENESIS_MESSAGE="ELECTRIC MONEY - Genesis Block. Utility protocol with 0.25% incoming payment levy (0.20% Treasury + 0.05% burn), 0.25% annual wallet balance levy (0.20% Treasury + 0.05% burn), and 72,270,024.841006 EM maximum cumulative issuance.";
static i64 now_s() {
    return (i64)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
static std::string hex(const unsigned char*p,size_t n) {
    static const char*h="0123456789abcdef";
    std::string s;
    s.resize(n*2);
    for(size_t i=0;i<n;i++) {
        s[2*i]=h[p[i]>>4];
        s[2*i+1]=h[p[i]&15];
    }
    return s;
}
static std::vector<unsigned char> unhex(const std::string&s) {
    if(s.size()%2)throw std::runtime_error("odd hex");
    std::vector<unsigned char>v(s.size()/2);
    for(size_t i=0;i<v.size();i++) {
        auto cv=[](char c)->int {
            if(c>='0'&&c<='9')return c-'0';
            if(c>='a'&&c<='f')return c-'a'+10;
            if(c>='A'&&c<='F')return c-'A'+10;
            return -1;
        };
        int a=cv(s[2*i]),b=cv(s[2*i+1]);
        if(a<0||b<0)throw std::runtime_error("bad hex");
        v[i]=(a<<4)|b;
    }
    return v;
}
static std::string json_escape(const std::string&s) {
    std::ostringstream o;
    o<<'"';
    for(unsigned char c:s) {
        switch(c) {
            case '"':o<<"\\\"";
            break;
            case '\\':o<<"\\\\";
            break;
            case '\b':o<<"\\b";
            break;
            case '\f':o<<"\\f";
            break;
            case '\n':o<<"\\n";
            break;
            case '\r':o<<"\\r";
            break;
            case '\t':o<<"\\t";
            break;
            default: if(c<0x20)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c<<std::dec<<std::setfill(' ');
            else o<<c;
        }
    }
    o<<'"';
    return o.str();
}
static std::string sha3_512(const std::string&s) {
    EVP_MD_CTX*c=EVP_MD_CTX_new();
    if(!c)throw std::runtime_error("EVP_MD_CTX");
    if(EVP_DigestInit_ex(c,EVP_sha3_512(),nullptr)<=0||EVP_DigestUpdate(c,s.data(),s.size())<=0)throw std::runtime_error("SHA3 init");
    unsigned char out[64];
    unsigned int n=0;
    if(EVP_DigestFinal_ex(c,out,&n)<=0) {
        EVP_MD_CTX_free(c);
        throw std::runtime_error("SHA3 final");
    }
    EVP_MD_CTX_free(c);
    return hex(out,n);
}
static std::string canonical(const std::map<std::string,std::string>&raw) {
    std::ostringstream o;
    o<<'{';
    bool first=true;
    for(auto&[k,v]:raw) {
        if(!first)o<<',';
        first=false;
        o<<json_escape(k)<<':'<<v;
    }
    o<<'}';
    return o.str();
}
static std::string hash_obj(const std::map<std::string,std::string>&m) {
    return sha3_512(canonical(m));
}
static bool is_hex(const std::string&s,size_t len) {
    if(s.size()!=len)return false;
    for(char c:s)if(!std::isxdigit((unsigned char)c))return false;
    return true;
}
static bool json_get_string(json_object*o,const char*k,std::string&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_string)) return false;
    out=json_object_get_string(v);
    return true;
}
static bool json_get_i64(json_object*o,const char*k,i64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    out=json_object_get_int64(v);
    return true;
}
static bool json_get_u64(json_object*o,const char*k,u64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    int64_t x=json_object_get_int64(v);
    if(x<0) return false;
    out=static_cast<u64>(x);
    return true;
}
static bool json_get_int(json_object*o,const char*k,int&out) {
    i64 x=0;
    if(!json_get_i64(o,k,x) || x<INT_MIN || x>INT_MAX) return false;
    out=static_cast<int>(x);
    return true;
}

static i64 checked_amount(i64 x) {
    if(x<=0||x>MAX_TX_AMOUNT)throw std::runtime_error("amount outside allowed range");
    return x;
}
class Wallet {
    EVP_PKEY*pkey=nullptr;
    public:
    static constexpr size_t PUB_HEX=MLDSA65_PUBLIC_KEY_BYTES*2;
    static constexpr size_t SIG_HEX=MLDSA65_SIGNATURE_BYTES*2;
    std::string public_key_hex,address;
    Wallet() {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
        if(!c)throw std::runtime_error("OpenSSL 3.5+ ML-DSA-65 unavailable");
        if(EVP_PKEY_keygen_init(c)<=0||EVP_PKEY_keygen(c,&pkey)<=0) {
            EVP_PKEY_CTX_free(c);
            throw std::runtime_error("ML-DSA keygen failed");
        }
        EVP_PKEY_CTX_free(c);
        size_t n=0;
        if(EVP_PKEY_get_raw_public_key(pkey,nullptr,&n)<=0||n!=MLDSA65_PUBLIC_KEY_BYTES)throw std::runtime_error("bad ML-DSA public key size");
        std::vector<unsigned char>pub(n);
        if(EVP_PKEY_get_raw_public_key(pkey,pub.data(),&n)<=0)throw std::runtime_error("public key export failed");
        public_key_hex=hex(pub.data(),pub.size());
        address=sha3_512(std::string((char*)pub.data(),pub.size()));
    }
    ~Wallet() {
        EVP_PKEY_free(pkey);
    }
    Wallet(const Wallet&)=delete;
    Wallet&operator=(const Wallet&)=delete;
    std::string sign(const std::string&msg)const {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_pkey(nullptr,pkey,nullptr);
        EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
        if(!c||!alg)throw std::runtime_error("ML-DSA sign setup");
        if(EVP_PKEY_sign_message_init(c,alg,nullptr)<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign init");
        }
        size_t n=0;
        if(EVP_PKEY_sign(c,nullptr,&n,(const unsigned char*)msg.data(),msg.size())<=0||n!=MLDSA65_SIGNATURE_BYTES) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA signature size");
        }
        std::vector<unsigned char>s(n);
        if(EVP_PKEY_sign(c,s.data(),&n,(const unsigned char*)msg.data(),msg.size())<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign");
        }
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(alg);
        return hex(s.data(),n);
    }
    static bool verify(const std::string&pubhex,const std::string&msg,const std::string&sighex) {
        try {
            if(!is_hex(pubhex,PUB_HEX)||!is_hex(sighex,SIG_HEX))return false;
            auto pub=unhex(pubhex),sig=unhex(sighex);
            EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
            if(!c)return false;
            if(EVP_PKEY_fromdata_init(c)<=0)return false;
            OSSL_PARAM params[2];
            params[0]=OSSL_PARAM_construct_octet_string("pub",pub.data(),pub.size());
            params[1]=OSSL_PARAM_construct_end();
            EVP_PKEY*pk=nullptr;
            if(EVP_PKEY_fromdata(c,&pk,EVP_PKEY_PUBLIC_KEY,params)<=0) {
                EVP_PKEY_CTX_free(c);
                return false;
            }
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
            c=EVP_PKEY_CTX_new_from_pkey(nullptr,pk,nullptr);
            bool ok=false;
            if(c&&alg&&EVP_PKEY_verify_message_init(c,alg,nullptr)>0)ok=EVP_PKEY_verify(c,sig.data(),sig.size(),(const unsigned char*)msg.data(),msg.size())==1;
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            EVP_PKEY_free(pk);
            return ok;
        } catch(...) {
            return false;
        }
    }
};
struct Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;
    std::string sender()const {
        return sha3_512(std::string((char*)unhex(sender_pubkey).data(),unhex(sender_pubkey).size()));
    }
    i64 burned()const {
        return (amount*TX_BURN_BPS)/10000;
    }
    i64 receiver_tax()const {
        return (amount*RECEIVER_TAX_BPS)/10000;
    }
    i64 net_amount()const {
        return amount-receiver_tax()-burned();
    }
    std::string signing_json()const {
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
    std::string id_json()const {
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
    bool valid(i64 now=now_s(),bool age=true)const {
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
    std::string json()const {
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
};
struct MiningShare {
    std::string miner,job_id,share_hash,share_id;
    int difficulty=1;
    u64 nonce=0;
    static std::string challenge(const std::string&job,int d) {
        return sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+job+"-"+std::to_string(d));
    }
    std::string calc_hash()const {
        return sha3_512(challenge(job_id,difficulty)+miner+std::to_string(nonce));
    }
    std::string calc_id()const {
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
    bool valid(const std::string&job,int d)const {
        return is_hex(miner,128)&&is_hex(job_id,128)&&difficulty>=1&&job_id==job&&difficulty==d&&share_hash==calc_hash()&&share_hash.rfind(std::string(difficulty,'0'),0)==0&&share_id==calc_id();
    }
    std::string json()const {
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
};
static i64 subsidy(int h) {
    if(h<=0)return BASE_REWARD;
    int halv=h/HALVING_INTERVAL;
    if(halv>=63)return 0;
    return INITIAL_BLOCK_REWARD>>halv;
}
static cpp_int block_work(int d) {
    return cpp_int(1) << (4*d);
}
struct Block {
    int index=0;
    std::string previous_hash,merkle_root,extra_data,block_hash;
    std::vector<std::string>transactions;
    i64 timestamp=0;
    u64 nonce=0;
    int difficulty=1;
    std::string header_json()const {
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
    std::string calc_hash()const {
        return sha3_512(header_json());
    }
    void mine(const std::function<bool()>&stop=[]() {
        return false;
    }
    ) {
        for(;;) {
            if(stop())throw std::runtime_error("mining interrupted");
            block_hash=calc_hash();
            if(block_hash.rfind(std::string(difficulty,'0'),0)==0)return;
            ++nonce;
        }
    }
    std::string json()const {
        std::ostringstream o;
        o<<"{\"difficulty\":"<<difficulty<<",\"extra_data\":"<<json_escape(extra_data)<<",\"hash\":"<<json_escape(block_hash)<<",\"index\":"<<index<<",\"merkle_root\":"<<json_escape(merkle_root)<<",\"nonce\":"<<nonce<<",\"previous_hash\":"<<json_escape(previous_hash)<<",\"timestamp\":"<<timestamp<<",\"transactions\":[";
        for(size_t i=0;i<transactions.size();++i) {
            if(i)o<<',';
            o<<transactions[i];
        }
        o<<"]}";
        return o.str();
    }
};
static std::string merkle(const std::vector<std::string>&items) {
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

static bool parse_block(const std::string&s,Block&b) {
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
static std::string chain_json(const std::vector<Block>&c) {
    std::ostringstream o; o<<"[";
    for(size_t i=0;i<c.size();++i){ if(i)o<<','; o<<c[i].json(); if(o.tellp()>static_cast<std::streamoff>(MAX_CHAIN_SYNC_BYTES)) return {}; }
    o<<"]"; return o.str();
}
static bool parse_chain(const std::string&s,std::vector<Block>&out) {
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

struct L2Deposit;
struct L2Withdrawal;
struct L2Transaction;
static bool parse_l2_deposit(json_object*o,L2Deposit&d);
static bool parse_l2_withdrawal(json_object*o,L2Withdrawal&w);
static bool prior_release_exists(const std::vector<Block>&prefix,const std::string&claim_id);
static bool find_finalized_withdrawal(const std::vector<Block>&prefix,const std::string&commitment_hash,const std::string&claim_id,const std::string&recipient,i64 amount);
static bool find_finalized_deposit(const std::vector<Block>&prefix,const L2Deposit&d);
static bool verify_l2_deposit_manifest(json_object*o,const std::vector<Block>&prefix);
static std::string withdrawal_release_id_fields(const std::string&commitment_hash,const std::string&recipient,const std::string&claim,i64 amount);
static bool verify_l2_commitment(json_object*o,const std::string&expected_prev_root);
static std::string last_l2_state_root(const std::vector<Block>&prefix);

class Blockchain {
    public:
    std::vector<Block>chain;
    std::map<std::string,Transaction>pending;
    std::map<std::string,Block>orphans;
    std::map<std::string,i64>balances,nonces;
    i64 total_issued=0,total_burned=0,treasury_balance=0;
    std::map<std::string,cpp_int>miner_work;
    std::map<std::string,i64>wallet_anchor;
    std::map<std::string,MiningShare>pending_shares;
    mutable std::mutex mu;
    std::string db;
    Blockchain(std::string f="electric_money_v19.json"):db(std::move(f)) {
        if(std::filesystem::exists(db)) {
            if(!load()) throw std::runtime_error("database exists but failed validation");
        } else {
            genesis();
        }
    }
    int height()const {
        return (int)chain.size()-1;
    }
    i64 supply()const {
        return total_issued-total_burned;
    }
    cpp_int cumulative_work()const {
        cpp_int x=0;
        for(auto&b:chain)x+=block_work(b.difficulty);
        return x;
    }
    static int share_diff(int d) {
        return std::max(1,d-SHARE_DIFFICULTY_OFFSET);
    }
    static int expected_diff(const std::vector<Block>&c,int h) {
        if(h==0)return GENESIS_DIFFICULTY;
        int d=c[h-1].difficulty;
        if(h%DIFFICULTY_INTERVAL)return d;
        auto&first=c[h-DIFFICULTY_INTERVAL];
        auto&last=c[h-1];
        i64 actual=std::max<i64>(1,last.timestamp-first.timestamp),expected=(i64)TARGET_BLOCK_TIME*(DIFFICULTY_INTERVAL-1);
        if(actual<expected/2)++d;
        else if(actual>expected*2)--d;
        return std::clamp(d,MIN_DIFFICULTY,MAX_DIFFICULTY);
    }
    static i64 mtp(const std::vector<Block>&c) {
        std::vector<i64>t;
        for(int i=std::max(0,(int)c.size()-MTP_WINDOW);i<(int)c.size();++i)t.push_back(c[i].timestamp);
        std::sort(t.begin(),t.end());
        return t[t.size()/2];
    }
    void genesis() {
        std::string tid=hash_obj( {
             {
                "amount",std::to_string(BASE_REWARD)
            }
            , {
                "message",json_escape(GENESIS_MESSAGE)
            }
            , {
                "recipient",json_escape("Miner_Genesis")
            }
        }
        );
        std::string tx=canonical( {
             {
                "amount",std::to_string(BASE_REWARD)
            }
            , {
                "memo",json_escape(GENESIS_MESSAGE)
            }
            , {
                "recipient",json_escape("Miner_Genesis")
            }
            , {
                "tx_id",json_escape(tid)
            }
            , {
                "type",json_escape("genesis")
            }
        }
        );
        Block b;
        b.index=0;
        b.previous_hash=ZERO_HASH;
        b.transactions= {
            tx
        };
        b.timestamp=0;
        b.difficulty=GENESIS_DIFFICULTY;
        b.merkle_root=merkle( {
            tid
        }
        );
        b.extra_data=GENESIS_MESSAGE;
        b.mine();
        chain= {
            b
        };
        balances["Miner_Genesis"]=BASE_REWARD;
        total_issued=BASE_REWARD;
        wallet_anchor["Miner_Genesis"]=0;
        save();
    }
    static void credit(std::map<std::string,i64>&b,const std::string&a,i64 x) {
        if(x<0 || x>MAX_SUPPLY || b[a]<0 || b[a]>MAX_SUPPLY-x)throw std::runtime_error("balance overflow");
        b[a]+=x;
    }
    static void debit(std::map<std::string,i64>&b,const std::string&a,i64 x) {
        if(x<0||b[a]<x)throw std::runtime_error("insufficient balance");
        b[a]-=x;
    }
    static std::pair<i64,i64> annual_split(i64 bal) {
        return  {
            (bal*RECEIVER_TAX_BPS)/10000,(bal*TX_BURN_BPS)/10000
        };
    }
    // V17.1: apply at most MAX_TAX_CYCLES_PER_BLOCK (default 1) annual tax
    // cycle per wallet per block. Prevents multi-year DoS loops while remaining
    // deterministic. Missed years are collected gradually over subsequent blocks.
    static void annual(std::map<std::string,i64>&b,std::map<std::string,i64>&a,i64&treas,i64&burn,i64 ts) {
        for(auto&[addr,anchor0]:a) {
            i64 anchor=anchor0;
            int cycles_applied=0;
            // Avoid anchor + YEAR_SECONDS overflow. Consensus uses subtraction
            // only after establishing ts >= anchor.
            while(cycles_applied<MAX_TAX_CYCLES_PER_BLOCK && ts>=anchor && (ts-anchor)>=YEAR_SECONDS) {
                i64 bal=b[addr];
                if(bal>0) {
                    auto [tt,br]=annual_split(bal);
                    if(tt<0 || br<0 || tt>bal || br>bal-tt) throw std::runtime_error("annual tax arithmetic overflow");
                    i64 tax=tt+br;
                    if(tax>bal) throw std::runtime_error("annual tax exceeds balance");
                    b[addr]=bal-tax;
                    if(treas>MAX_SUPPLY-tt || burn>MAX_SUPPLY-br) throw std::runtime_error("annual treasury/burn overflow");
                    treas+=tt;
                    burn+=br;
                }
                if(anchor>std::numeric_limits<i64>::max()-YEAR_SECONDS) {
                    anchor=std::numeric_limits<i64>::max();
                    cycles_applied++;
                    break;
                }
                anchor+=YEAR_SECONDS;
                cycles_applied++;
            }
            anchor0=anchor;
        }
    }
    static void distribute(std::map<std::string,i64>&b,i64&treas,std::map<std::string,cpp_int>&work) {
        if(treas<=0)return;
        cpp_int total=0;
        for(auto&[m,w]:work)if(w>0)total+=w;
        if(total<=0)return;
        i64 distributed=0;
        std::pair<std::string,cpp_int>winner {
            "",-1
        };
        for(auto&[m,w]:work)if(w>0) {
            if(w>winner.second||(w==winner.second&&m<winner.first))winner= {
                m,w
            };
            cpp_int share_mp=(cpp_int(treas)*w)/total;
            i64 share=share_mp.convert_to<i64>();
            credit(b,m,share);
            distributed+=share;
        }
        if(treas-distributed>0)credit(b,winner.first,treas-distributed);
        treas=0;
        work.clear();
    }
    static bool apply_tx(const Transaction&t,std::map<std::string,i64>&b,std::map<std::string,i64>&n,i64&burn,i64&treas) {
        std::string s=t.sender();
        if(n[s]!=t.nonce||b[s]<t.amount||t.nonce==std::numeric_limits<i64>::max())return false;
        const i64 net=t.net_amount(), br=t.burned(), tt=t.receiver_tax();
        if(net<0 || br<0 || tt<0 || net>t.amount || br>t.amount || tt>t.amount ||
           br>MAX_SUPPLY-burn || tt>MAX_SUPPLY-treas)return false;
        debit(b,s,t.amount);
        try { credit(b,t.recipient,net); }
        catch(...) { return false; }
        n[s]=t.nonce+1;
        burn+=br;
        treas+=tt;
        return true;
    }
    bool validate_block(const Block&b,const Block&p,const std::vector<Block>&prefix,std::map<std::string,i64>bal,std::map<std::string,i64>nc,i64 issued,i64 burned,i64 treas,std::map<std::string,cpp_int>mw,std::map<std::string,i64>anchors,std::map<std::string,i64>*outbal=nullptr,std::map<std::string,i64>*outnc=nullptr,i64*outissued=nullptr,i64*outburn=nullptr,i64*outtreas=nullptr,std::map<std::string,cpp_int>*outmw=nullptr,std::map<std::string,i64>*outanchors=nullptr,i64 now=now_s())const {
        if(b.index!=p.index+1||b.previous_hash!=p.block_hash||b.difficulty<1||b.difficulty>MAX_DIFFICULTY||b.difficulty!=expected_diff(prefix,b.index)||b.timestamp<mtp(prefix)||b.timestamp>now+MAX_FUTURE_BLOCK_TIME)return false;
        if(b.transactions.empty()||b.transactions.size()>MAX_TX_PER_BLOCK+MAX_SHARES_PER_BLOCK+2||b.json().size()>MAX_BLOCK_BYTES)return false;
        std::vector<std::string>ids;
        for(auto&s:b.transactions) {
            json_object*o=json_tokener_parse(s.c_str());
            if(!o)return false;
            json_object*x=nullptr;
            std::string id;
            if(json_object_object_get_ex(o,"tx_id",&x))id=json_object_get_string(x);
            else if(json_object_object_get_ex(o,"share_id",&x))id=json_object_get_string(x);
            json_object_put(o);
            if(id.empty())return false;
            ids.push_back(id);
        }
        if(b.merkle_root!=merkle(ids)||b.calc_hash()!=b.block_hash||b.block_hash.rfind(std::string(b.difficulty,'0'),0)!=0)return false;
        json_object*r=json_tokener_parse(b.transactions.back().c_str());
        if(!r)return false;
        json_object*x=nullptr;
        if(!json_object_object_get_ex(r,"type",&x)||std::string(json_object_get_string(x))!="reward") {
            json_object_put(r);
            return false;
        }
        if(!json_object_object_get_ex(r,"recipient",&x)) {
            json_object_put(r);
            return false;
        }
        std::string miner=json_object_get_string(x);
        json_object_put(r);
        if(!is_hex(miner,128))return false;
        std::set<std::string>seen;
        int shares=0; size_t releases=0;
        i64 burn=burned;
        // Deterministic Genesis-tax anchor: the first post-genesis block starts
        // the annual-tax clock for Miner_Genesis. Never use wall-clock time here.
        if(b.index==1) {
            auto it=anchors.find("Miner_Genesis");
            if(it==anchors.end() || it->second==0) anchors["Miner_Genesis"]=b.timestamp;
        }
        for(size_t i=0;i+1<b.transactions.size();++i) {
            json_object*o=json_tokener_parse(b.transactions[i].c_str());
            if(!o)return false;
            json_object*t=nullptr;
            json_object_object_get_ex(o,"type",&t);
            std::string typ=t?json_object_get_string(t):"";
            json_object_object_get_ex(o,"tx_id",&x);
            std::string id=x?json_object_get_string(x):"";
            if(id.empty()||!seen.insert(id).second) {
                json_object_put(o);
                return false;
            }
            if(typ=="transfer") {
                Transaction q;
                if(!json_get_string(o,"sender_pubkey",q.sender_pubkey) || !json_get_string(o,"recipient",q.recipient) ||
                   !json_get_i64(o,"amount",q.amount) || !json_get_i64(o,"nonce",q.nonce) ||
                   !json_get_i64(o,"timestamp",q.timestamp) || !json_get_string(o,"signature",q.signature)) {
                    json_object_put(o); return false;
                }
                q.tx_id=id;
                if(!q.valid(b.timestamp,true)||!apply_tx(q,bal,nc,burn,treas)) {
                    json_object_put(o);
                    return false;
                }
                if(!anchors.count(q.recipient))anchors[q.recipient]=b.timestamp;
            } 
            else if(typ=="mining_share") {
                if(++shares>MAX_SHARES_PER_BLOCK) {
                    json_object_put(o);
                    return false;
                }
                MiningShare s;
                if(!json_get_string(o,"miner",s.miner) || !json_get_string(o,"job_id",s.job_id) ||
                   !json_get_int(o,"difficulty",s.difficulty) || !json_get_u64(o,"nonce",s.nonce) ||
                   !json_get_string(o,"share_hash",s.share_hash) || !json_get_string(o,"share_id",s.share_id)) {
                    json_object_put(o); return false;
                }
                if(!s.valid(p.block_hash,share_diff(p.difficulty))) {
                    json_object_put(o);
                    return false;
                }
                mw[s.miner]+=block_work(s.difficulty);
            } 
            else if(typ=="l2_withdrawal_release") {
                if(++releases>MAX_L2_RELEASES_PER_BLOCK) { json_object_put(o); return false; }
                std::string claim,commitment,recipient,id; i64 amount=0;
                if(!json_get_string(o,"claim_id",claim)||!json_get_string(o,"commitment_hash",commitment)||!json_get_string(o,"recipient",recipient)||!json_get_string(o,"tx_id",id)||!json_get_i64(o,"amount",amount) || !is_hex(claim,128)||!is_hex(commitment,128)||!is_hex(recipient,128)||!is_hex(id,128)||amount<=0||amount>MAX_SUPPLY || id!=withdrawal_release_id_fields(commitment,recipient,claim,amount) || prior_release_exists(prefix,claim) || !find_finalized_withdrawal(prefix,commitment,claim,recipient,amount)) { json_object_put(o); return false; }
                if(bal[L2_BRIDGE_ADDRESS]<amount) { json_object_put(o); return false; }
                debit(bal,L2_BRIDGE_ADDRESS,amount);
                credit(bal,recipient,amount);
            }
            else if(typ=="l2_commitment") {
                if(!verify_l2_commitment(o,last_l2_state_root(prefix))) { json_object_put(o); return false; }
                if(!verify_l2_deposit_manifest(o,prefix)) { json_object_put(o); return false; }
            } 
            else  {
                json_object_put(o);
                return false;
            }
            json_object_put(o);
        }
        json_object*ro=json_tokener_parse(b.transactions.back().c_str());
        if(!ro || !json_object_is_type(ro,json_type_object)) { if(ro) json_object_put(ro); return false; }
        std::string rtype,recipient,rid; i64 amount=0,iss=0;
        bool reward_fields=json_get_string(ro,"type",rtype) && rtype=="reward" &&
            json_get_string(ro,"recipient",recipient) && json_get_string(ro,"tx_id",rid) &&
            json_get_i64(ro,"amount",amount) && json_get_i64(ro,"issuance",iss);
        i64 issuance=(issued>=MAX_SUPPLY)?0:std::min<i64>(subsidy(b.index),MAX_SUPPLY-issued);
        json_object_put(ro);
        if(!reward_fields || recipient!=miner) return false;
        if(issuance<0||amount!=issuance||iss!=issuance||rid!=hash_obj( {
             {
                "amount",std::to_string(issuance)
            }
            , {
                "block_index",std::to_string(b.index)
            }
            , {
                "issuance",std::to_string(issuance)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "type",json_escape("reward")
            }
        }
        ))return false;
        issued+=issuance;
        credit(bal,miner,issuance);
        if(!anchors.count(miner))anchors[miner]=b.timestamp;
        mw[miner]+=block_work(b.difficulty);
        annual(bal,anchors,treas,burn,b.timestamp);
        if(issued>MAX_SUPPLY||burn>issued||treas<0||burn<0)return false;
        if(b.index>0&&b.index%MINER_REWARD_EPOCH_BLOCKS==0)distribute(bal,treas,mw);
        if(outbal)*outbal=std::move(bal);
        if(outnc)*outnc=std::move(nc);
        if(outissued)*outissued=issued;
        if(outburn)*outburn=burn;
        if(outtreas)*outtreas=treas;
        if(outmw)*outmw=std::move(mw);
        if(outanchors)*outanchors=std::move(anchors);
        return true;
    }
    static bool validate_genesis(const Block&b) {
        if(b.index!=0 || b.previous_hash!=ZERO_HASH || b.timestamp!=0 || b.difficulty!=GENESIS_DIFFICULTY || b.nonce!=GENESIS_NONCE || b.extra_data!=GENESIS_MESSAGE || b.block_hash!=GENESIS_HASH || b.merkle_root!=GENESIS_MERKLE) return false;
        if(b.calc_hash()!=GENESIS_HASH || b.block_hash.rfind(std::string(GENESIS_DIFFICULTY,'0'),0)!=0) return false;
        if(b.transactions.size()!=1) return false;
        json_object*o=json_tokener_parse(b.transactions[0].c_str());
        if(!o || !json_object_is_type(o,json_type_object)) { if(o) json_object_put(o); return false; }
        std::string type,recipient,tid,memo; i64 amount=0;
        bool ok=json_get_string(o,"type",type) && type=="genesis" &&
                json_get_string(o,"recipient",recipient) && recipient=="Miner_Genesis" &&
                json_get_string(o,"tx_id",tid) && json_get_string(o,"memo",memo) && memo==GENESIS_MESSAGE &&
                json_get_i64(o,"amount",amount) && amount==BASE_REWARD;
        json_object_put(o);
        if(!ok) return false;
        std::string expected_tid=hash_obj({{"amount",std::to_string(BASE_REWARD)}, {"message",json_escape(GENESIS_MESSAGE)}, {"recipient",json_escape("Miner_Genesis")}});
        std::string expected_tx=canonical({{"amount",std::to_string(BASE_REWARD)}, {"memo",json_escape(GENESIS_MESSAGE)}, {"recipient",json_escape("Miner_Genesis")}, {"tx_id",json_escape(expected_tid)}, {"type",json_escape("genesis")}});
        return tid==expected_tid && merkle({tid})==GENESIS_MERKLE;
    }

    bool replay(const std::vector<Block>&c,std::map<std::string,i64>&ob,std::map<std::string,i64>&on,i64&oi,i64&oburn,i64&ot,std::map<std::string,cpp_int>&omw,std::map<std::string,i64>&oa)const {
        if(c.empty() || !validate_genesis(c[0]))return false;
        ob= {
             {
                 {
                    "Miner_Genesis",BASE_REWARD
                }
            }
        };
        on.clear();
        oi=BASE_REWARD;
        oburn=0;
        ot=0;
        omw.clear();
        oa= {
             {
                 {
                    "Miner_Genesis",0
                }
            }
        };
        for(size_t i=1;i<c.size();++i) {
            if(!validate_block(c[i],c[i-1],std::vector<Block>(c.begin(),c.begin()+i),ob,on,oi,oburn,ot,omw,oa,&ob,&on,&oi,&oburn,&ot,&omw,&oa))return false;
        }
        return true;
    }
    bool validate_chain(const std::vector<Block>&c)const {
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        return replay(c,b,n,i,br,t,m,a);
    }
    i64 next_nonce(const std::string&a) {
        std::lock_guard<std::mutex>g(mu);
        i64 n=nonces[a];
        for(auto&[id,t]:pending)if(t.sender()==a)n=std::max(n,t.nonce+1);
        return n;
    }
    bool add_transaction(const Transaction&t) {
        std::lock_guard<std::mutex>g(mu);
        if(pending.count(t.tx_id)||!t.valid())return false;
        std::map<std::string,i64>b=balances,n=nonces;
        std::vector<Transaction> pend;
        for(auto&[id,p]:pending) pend.push_back(p);
        std::sort(pend.begin(),pend.end(),[](const Transaction&a,const Transaction&b) {
            return std::make_tuple(a.timestamp,a.sender(),a.nonce,a.tx_id)<std::make_tuple(b.timestamp,b.sender(),b.nonce,b.tx_id);
        }
        );
        i64 dummy_burn=0,dummy_treas=0;
        for(auto&p:pend) if(p.sender()==t.sender() && p.nonce>=t.nonce) continue;
        else  {
            auto vb=b,vn=n;
            if(p.valid() && vn[p.sender()]==p.nonce && vb[p.sender()]>=p.amount) apply_tx(p,b,n,dummy_burn,dummy_treas);
        }
        if(n[t.sender()]!=t.nonce||b[t.sender()]<t.amount)return false;
        pending[t.tx_id]=t;
        save();
        return true;
    }
    Block candidate(const std::string&miner,const std::vector<std::string>&l2= {
    }
    ) {
        std::lock_guard<std::mutex>g(mu);
        Block b;
        b.index=chain.size();
        b.previous_hash=chain.back().block_hash;
        b.timestamp=std::max(now_s(),mtp(chain));
        b.difficulty=expected_diff(chain,b.index);
        b.extra_data="ELECTRIC-MONEY-PoW-"+NETWORK_ID;
        std::vector<std::string>txs;
        std::map<std::string,i64>bb=balances,nn=nonces;
        i64 burn=0,treas=0;
        std::vector<Transaction>ordered;
        for(auto&[id,t]:pending)ordered.push_back(t);
        std::sort(ordered.begin(),ordered.end(),[](const Transaction&a,const Transaction&b) {
            return std::make_tuple(a.timestamp,a.sender(),a.nonce,a.tx_id)<std::make_tuple(b.timestamp,b.sender(),b.nonce,b.tx_id);
        }
        );
        for(auto&t:ordered) {
            if(t.valid()&&nn[t.sender()]==t.nonce&&bb[t.sender()]>=t.amount&&txs.size()<MAX_TX_PER_BLOCK) {
                apply_tx(t,bb,nn,burn,treas);
                txs.push_back(canonical( {
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
                    , {
                        "tx_id",json_escape(t.tx_id)
                    }
                    , {
                        "type",json_escape("transfer")
                    }
                }
                ));
            }
        }
        for(auto&s:l2)txs.push_back(s);
        for(auto&[id,s]:pending_shares)if(s.valid(chain.back().block_hash,share_diff(chain.back().difficulty))&&txs.size()<MAX_TX_PER_BLOCK+MAX_SHARES_PER_BLOCK)txs.push_back(s.json());
        i64 iss=std::min<i64>(subsidy(b.index),MAX_SUPPLY-total_issued);
        std::string rid=hash_obj( {
             {
                "amount",std::to_string(iss)
            }
            , {
                "block_index",std::to_string(b.index)
            }
            , {
                "issuance",std::to_string(iss)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "type",json_escape("reward")
            }
        }
        );
        txs.push_back(canonical( {
             {
                "amount",std::to_string(iss)
            }
            , {
                "issuance",std::to_string(iss)
            }
            , {
                "recipient",json_escape(miner)
            }
            , {
                "tx_id",json_escape(rid)
            }
            , {
                "type",json_escape("reward")
            }
        }
        ));
        b.transactions=txs;
        std::vector<std::string>ids;
        for(auto&s:txs) {
            json_object*o=json_tokener_parse(s.c_str());
            json_object*x=nullptr;
            json_object_object_get_ex(o,"tx_id",&x);
            ids.push_back(json_object_get_string(x));
            json_object_put(o);
        }
        b.merkle_root=merkle(ids);
        return b;
    }
    Block mine_pending(const std::string&miner,const std::function<bool()>&stop=[]() {
        return false;
    }
    ) {
        Block b=candidate(miner);
        b.mine(stop);
        std::lock_guard<std::mutex>g(mu);
        std::map<std::string,i64>bb,nn,an;
        std::map<std::string,cpp_int>mw;
        i64 issued,burn,treas;
        if(!validate_block(b,chain.back(),chain,balances,nonces,total_issued,total_burned,treasury_balance,miner_work,wallet_anchor,&bb,&nn,&issued,&burn,&treas,&mw,&an))throw std::runtime_error("self-mined block rejected");
        chain.push_back(b);
        balances=std::move(bb);
        nonces=std::move(nn);
        total_issued=issued;
        total_burned=burn;
        treasury_balance=treas;
        miner_work=std::move(mw);
        wallet_anchor=std::move(an);
        for(auto it=pending.begin();it!=pending.end();) {
            bool found=false;
            const std::string needle="\"tx_id\":"+json_escape(it->first);
            for(auto&s:b.transactions) {
                if(s.find(needle)!=std::string::npos) { found=true; break; }
            }
            if(found)it=pending.erase(it);
            else ++it;
        }
        pending_shares.clear();
        save();
        return b;
    }
    Block mine_external(const std::string&miner,const std::vector<std::string>&extra) {
        Block b=candidate(miner,extra); b.mine();
        std::lock_guard<std::mutex>g(mu);
        std::map<std::string,i64>bb,nn,an; std::map<std::string,cpp_int>mw;
        i64 issued,burn,treas;
        if(!validate_block(b,chain.back(),chain,balances,nonces,total_issued,total_burned,treasury_balance,miner_work,wallet_anchor,&bb,&nn,&issued,&burn,&treas,&mw,&an)) throw std::runtime_error("external block rejected");
        chain.push_back(b); balances=std::move(bb); nonces=std::move(nn); total_issued=issued; total_burned=burn; treasury_balance=treas; miner_work=std::move(mw); wallet_anchor=std::move(an);
        for(auto it=pending.begin();it!=pending.end();) {
            bool found=false; const std::string needle="\"tx_id\":"+json_escape(it->first);
            for(auto&raw:b.transactions) if(raw.find(needle)!=std::string::npos){found=true;break;}
            if(found)it=pending.erase(it); else ++it;
        }
        pending_shares.clear(); save(); return b;
    }
    bool accept_block(const Block&b) {
        std::lock_guard<std::mutex>g(mu);
        if(b.index<=height()) return false;
        if(b.index!=height()+1 || b.previous_hash!=chain.back().block_hash) {
            if(orphans.size()>=MAX_ORPHANS) orphans.erase(orphans.begin());
            orphans[b.block_hash]=b;
            return false;
        }
        std::map<std::string,i64>bb,nn,an; std::map<std::string,cpp_int>mw;
        i64 issued,burn,treas;
        if(!validate_block(b,chain.back(),chain,balances,nonces,total_issued,total_burned,treasury_balance,miner_work,wallet_anchor,&bb,&nn,&issued,&burn,&treas,&mw,&an)) return false;
        chain.push_back(b); balances=std::move(bb); nonces=std::move(nn); total_issued=issued; total_burned=burn; treasury_balance=treas; miner_work=std::move(mw); wallet_anchor=std::move(an);
        for(auto it=pending.begin();it!=pending.end();) {
            bool found=false; const std::string needle="\"tx_id\":"+json_escape(it->first);
            for(auto&s:b.transactions) if(s.find(needle)!=std::string::npos){found=true;break;}
            if(found)it=pending.erase(it); else ++it;
        }
        save(); return true;
    }
    std::vector<Block> snapshot_chain() const { std::lock_guard<std::mutex>g(mu); return chain; }
    std::vector<Block> snapshot_from(size_t start,size_t max_count) const { std::lock_guard<std::mutex>g(mu); if(start>=chain.size()) return {}; size_t end=std::min(chain.size(),start+max_count); return std::vector<Block>(chain.begin()+start,chain.begin()+end); }

    bool replace_chain(const std::vector<Block>&c) {
        std::lock_guard<std::mutex>g(mu);
        if(!validate_chain(c)||cumulative(c)<=cumulative(chain))return false;
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        if(!replay(c,b,n,i,br,t,m,a))return false;
        chain=c;
        balances=b;
        nonces=n;
        total_issued=i;
        total_burned=br;
        treasury_balance=t;
        miner_work=m;
        wallet_anchor=a;
        save();
        return true;
    }
    static cpp_int cumulative(const std::vector<Block>&c) {
        cpp_int x=0;
        for(auto&b:c)x+=block_work(b.difficulty);
        return x;
    }
    void save()const {
        std::ofstream f(db+".tmp");
        if(!f)return;
        f<<"{\"network_id\":"<<json_escape(NETWORK_ID)<<",\"protocol_version\":"<<PROTOCOL_VERSION<<",\"chain\":[";
        for(size_t i=0;i<chain.size();++i) {
            if(i)f<<',';
            f<<chain[i].json();
        }
        f<<"],\"pending\":[";
        size_t k=0;
        for(auto&[id,t]:pending) {
            if(k++)f<<',';
            f<<t.json();
        }
        f<<"],\"pending_shares\":[";
        k=0;
        for(auto&[id,s]:pending_shares) {
            if(k++)f<<',';
            f<<s.json();
        }
        f<<"]}";
        f.flush();
        if(!f.good()) throw std::runtime_error("database write failed");
        f.close();
        // V18 durability barrier: make the temporary file durable before the
        // atomic rename. This does not make the filesystem universally
        // transactional, but substantially reduces torn-write exposure.
        int fd=open((db+".tmp").c_str(),O_RDONLY);
        if(fd<0) throw std::runtime_error("database durability open failed");
        if(fsync(fd)!=0) { close(fd); throw std::runtime_error("database durability sync failed"); }
        close(fd);
        if(std::rename((db+".tmp").c_str(),db.c_str())!=0) throw std::runtime_error("database commit failed");
        int dfd=open(std::filesystem::path(db).parent_path().empty()?".":std::filesystem::path(db).parent_path().c_str(),O_RDONLY|O_DIRECTORY);
        if(dfd>=0) { fsync(dfd); close(dfd); }
    }
    bool load() {
        std::error_code ec;
        const auto sz=std::filesystem::file_size(db,ec);
        if(ec || sz>MAX_DB_BYTES)return false;
        std::ifstream f(db,std::ios::binary);
        if(!f)return false;
        std::string s;
        s.resize(static_cast<size_t>(sz));
        if(sz>0 && !f.read(s.data(),static_cast<std::streamsize>(sz)))return false;
        json_tokener*tok=json_tokener_new();
        if(!tok)return false;
        json_object*r=json_tokener_parse_ex(tok,s.data(),static_cast<int>(s.size()));
        enum json_tokener_error jerr=json_tokener_get_error(tok);
        json_tokener_free(tok);
        if(jerr!=json_tokener_success)return false;
        if(!r || !json_object_is_type(r,json_type_object)) { if(r) json_object_put(r); return false; }
        std::string network; i64 protocol=0;
        json_object*ch=nullptr;
        if(!json_get_string(r,"network_id",network) || network!=NETWORK_ID || !json_get_i64(r,"protocol_version",protocol) || protocol!=PROTOCOL_VERSION ||
           !json_object_object_get_ex(r,"chain",&ch) || !json_object_is_type(ch,json_type_array)) {
            json_object_put(r);
            return false;
        }
        std::vector<Block>c;
        for(size_t i=0;i<json_object_array_length(ch);++i) {
            json_object*o=json_object_array_get_idx(ch,i);
            if(!o || !json_object_is_type(o,json_type_object)) { json_object_put(r); return false; }
            Block b; std::string hash; i64 idx=0,ts=0; int diff=0; u64 nonce=0;
            if(!json_get_i64(o,"index",idx) || idx<0 || idx>INT_MAX || !json_get_string(o,"previous_hash",b.previous_hash) ||
               !json_get_i64(o,"timestamp",ts) || !json_get_u64(o,"nonce",nonce) || !json_get_int(o,"difficulty",diff) ||
               !json_get_string(o,"merkle_root",b.merkle_root) || !json_get_string(o,"extra_data",b.extra_data) ||
               !json_get_string(o,"hash",hash)) { json_object_put(r); return false; }
            json_object*x=nullptr;
            if(!json_object_object_get_ex(o,"transactions",&x) || !x || !json_object_is_type(x,json_type_array)) { json_object_put(r); return false; }
            b.index=static_cast<int>(idx); b.timestamp=ts; b.nonce=nonce; b.difficulty=diff; b.block_hash=hash;
            for(size_t j=0;j<json_object_array_length(x);++j) {
                json_object*tx=json_object_array_get_idx(x,j);
                if(!tx || !json_object_is_type(tx,json_type_object)) { json_object_put(r); return false; }
                b.transactions.push_back(json_object_to_json_string(tx));
            }
            c.push_back(std::move(b));
        }

        // Restore pending transactions and mining shares so a restart does not
        // silently discard locally accepted work. Entries are revalidated before
        // being admitted to memory and bounded by their configured capacities.
        std::map<std::string,Transaction>loaded_pending;
        json_object*pa=nullptr;
        if(json_object_object_get_ex(r,"pending",&pa)) {
            if(!pa || !json_object_is_type(pa,json_type_array) ||
               json_object_array_length(pa)>MAX_PENDING_TX) { json_object_put(r); return false; }
            for(size_t k=0;k<json_object_array_length(pa);++k) {
                json_object*o=json_object_array_get_idx(pa,k);
                if(!o || !json_object_is_type(o,json_type_object)) { json_object_put(r); return false; }
                Transaction t; i64 amount=0,nonce=0,ts=0;
                std::string recipient,pub,sig,id;
                if(!json_get_i64(o,"amount",amount)||!json_get_i64(o,"nonce",nonce)||
                   !json_get_string(o,"recipient",recipient)||!json_get_string(o,"sender_pubkey",pub)||
                   !json_get_string(o,"signature",sig)||!json_get_i64(o,"timestamp",ts)||
                   !json_get_string(o,"tx_id",id)) { json_object_put(r); return false; }
                t.amount=amount; t.nonce=nonce; t.timestamp=ts; t.recipient=recipient;
                t.sender_pubkey=pub; t.signature=sig; t.tx_id=id;
                if(!t.valid(now_s(),false) || loaded_pending.count(id)) { json_object_put(r); return false; }
                loaded_pending.emplace(id,std::move(t));
            }
        }
        std::map<std::string,MiningShare>loaded_shares;
        json_object*ps=nullptr;
        if(json_object_object_get_ex(r,"pending_shares",&ps)) {
            if(!ps || !json_object_is_type(ps,json_type_array) ||
               json_object_array_length(ps)>MAX_PENDING_SHARES) { json_object_put(r); return false; }
            for(size_t k=0;k<json_object_array_length(ps);++k) {
                json_object*o=json_object_array_get_idx(ps,k);
                if(!o || !json_object_is_type(o,json_type_object)) { json_object_put(r); return false; }
                MiningShare sh; i64 diff=0; u64 nonce=0;
                std::string miner,job,hash,id,type;
                if(!json_get_string(o,"miner",miner)||!json_get_string(o,"job_id",job)||
                   !json_get_i64(o,"difficulty",diff)||!json_get_u64(o,"nonce",nonce)||
                   !json_get_string(o,"share_hash",hash)||!json_get_string(o,"share_id",id)||
                   !json_get_string(o,"type",type) || type!="mining_share" ||
                   diff<MINING_SHARE_MIN_DIFFICULTY || diff>MAX_DIFFICULTY) { json_object_put(r); return false; }
                sh.miner=miner; sh.job_id=job; sh.difficulty=static_cast<int>(diff); sh.nonce=nonce;
                sh.share_hash=hash; sh.share_id=id;
                if(!is_hex(sh.miner,128)||!is_hex(sh.job_id,128)||!is_hex(sh.share_hash,128)||
                   !is_hex(sh.share_id,128)||loaded_shares.count(id)) { json_object_put(r); return false; }
                loaded_shares.emplace(id,std::move(sh));
            }
        }
        json_object_put(r);
        std::map<std::string,i64>b,n;
        std::map<std::string,cpp_int>m;
        std::map<std::string,i64>a;
        i64 i,br,t;
        if(c.empty()||!replay(c,b,n,i,br,t,m,a))return false;
        // Reconcile the restored mempool against the reconstructed L1 state.
        // Entries that are stale or no longer spendable are dropped instead of
        // making the entire database unbootable. Valid same-sender nonce chains
        // are admitted in deterministic order.
        std::vector<Transaction> pend;
        for(auto&[id,pt]:loaded_pending) {
            if(pt.timestamp < now_s()-MAX_TX_AGE) continue;
            pend.push_back(pt);
        }
        std::sort(pend.begin(),pend.end(),[](const Transaction&a,const Transaction&b){
            return std::make_tuple(a.timestamp,a.sender(),a.nonce,a.tx_id)<std::make_tuple(b.timestamp,b.sender(),b.nonce,b.tx_id);
        });
        std::map<std::string,i64> pb=b,pn=n;
        std::map<std::string,Transaction>reconciled;
        i64 dummy_burn=0,dummy_treas=0;
        for(auto&pt:pend) {
            auto itn=pn.find(pt.sender());
            i64 expected=(itn==pn.end()?0:itn->second);
            auto itb=pb.find(pt.sender());
            i64 avail=(itb==pb.end()?0:itb->second);
            if(pt.nonce!=expected || avail<pt.amount) continue;
            auto tb=pb,tn=pn;
            i64 xb=dummy_burn,xt=dummy_treas;
            if(apply_tx(pt,tb,tn,xb,xt)) {
                pb=std::move(tb); pn=std::move(tn);
                reconciled.emplace(pt.tx_id,pt);
            }
        }
        loaded_pending=std::move(reconciled);
        chain=c;
        balances=b;
        nonces=n;
        total_issued=i;
        total_burned=br;
        treasury_balance=t;
        miner_work=m;
        wallet_anchor=a;
        pending=std::move(loaded_pending);
        pending_shares=std::move(loaded_shares);
        return true;
    }
};
struct L2Deposit {
    std::string l1_tx_id, l1_block_hash, l2_recipient, claim_id; i64 amount=0;
    std::string json() const { return canonical({{"amount",std::to_string(amount)},{"claim_id",json_escape(claim_id)},{"l1_block_hash",json_escape(l1_block_hash)},{"l1_tx_id",json_escape(l1_tx_id)},{"l2_recipient",json_escape(l2_recipient)}}); }
};
struct L2Withdrawal {
    std::string l2_tx_id, l2_recipient, claim_id; i64 amount=0;
    std::string json() const { return canonical({{"amount",std::to_string(amount)},{"claim_id",json_escape(claim_id)},{"l2_recipient",json_escape(l2_recipient)},{"l2_tx_id",json_escape(l2_tx_id)}}); }
};
static std::string bridge_claim_id(const L2Deposit&d) { return sha3_512(canonical({{"amount",std::to_string(d.amount)},{"l1_block_hash",json_escape(d.l1_block_hash)},{"l1_tx_id",json_escape(d.l1_tx_id)},{"l2_recipient",json_escape(d.l2_recipient)}})); }
static std::string withdrawal_claim_id(const L2Withdrawal&w) { return sha3_512(canonical({{"amount",std::to_string(w.amount)},{"l2_recipient",json_escape(w.l2_recipient)},{"l2_tx_id",json_escape(w.l2_tx_id)}})); }
static bool parse_l2_deposit(json_object*o,L2Deposit&d) { return o&&json_object_is_type(o,json_type_object)&&json_get_string(o,"l1_tx_id",d.l1_tx_id)&&json_get_string(o,"l1_block_hash",d.l1_block_hash)&&json_get_string(o,"l2_recipient",d.l2_recipient)&&json_get_string(o,"claim_id",d.claim_id)&&json_get_i64(o,"amount",d.amount)&&d.amount>0&&d.amount<=MAX_SUPPLY&&is_hex(d.l1_tx_id,128)&&is_hex(d.l1_block_hash,128)&&is_hex(d.l2_recipient,128)&&is_hex(d.claim_id,128)&&d.claim_id==bridge_claim_id(d); }
static bool parse_l2_withdrawal(json_object*o,L2Withdrawal&w) { return o&&json_object_is_type(o,json_type_object)&&json_get_string(o,"l2_tx_id",w.l2_tx_id)&&json_get_string(o,"l2_recipient",w.l2_recipient)&&json_get_string(o,"claim_id",w.claim_id)&&json_get_i64(o,"amount",w.amount)&&w.amount>0&&w.amount<=MAX_SUPPLY&&is_hex(w.l2_tx_id,128)&&is_hex(w.l2_recipient,128)&&is_hex(w.claim_id,128)&&w.claim_id==withdrawal_claim_id(w); }
struct L2Transaction {
    std::string sender_pubkey,recipient,signature,tx_id;
    i64 amount=0,nonce=0,timestamp=0;
    std::string signing()const {
        return canonical({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"timestamp",std::to_string(timestamp)}});
    }
    bool valid()const {
        return amount>0&&is_hex(sender_pubkey,Wallet::PUB_HEX)&&is_hex(recipient,128)&&is_hex(signature,Wallet::SIG_HEX)&&
            tx_id==hash_obj({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"signature",json_escape(signature)},{"timestamp",std::to_string(timestamp)}})&&
            Wallet::verify(sender_pubkey,signing(),signature);
    }
    std::string json()const {
        return canonical({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"signature",json_escape(signature)},{"timestamp",std::to_string(timestamp)},{"tx_id",json_escape(tx_id)}});
    }
};
static std::string l2_state_root(const std::map<std::string,i64>&balances,const std::map<std::string,i64>&nonces) {
    std::ostringstream bo,no; bo<<"{"; bool f=true; for(auto&[a,v]:balances){if(!f)bo<<",";f=false;bo<<json_escape(a)<<":"<<v;} bo<<"}";
    no<<"{"; f=true; for(auto&[a,v]:nonces){if(!f)no<<",";f=false;no<<json_escape(a)<<":"<<v;} no<<"}";
    return hash_obj({{"balances",bo.str()},{"nonces",no.str()}});
}
static bool parse_l2_map(json_object*o,const char*key,std::map<std::string,i64>&out) {
    json_object*v=nullptr; if(!json_object_object_get_ex(o,key,&v)||!v||!json_object_is_type(v,json_type_object))return false;
    json_object_object_foreach(v,k,val){ if(!json_object_is_type(val,json_type_int))return false; i64 x=json_object_get_int64(val); if(x<0||x>MAX_SUPPLY)return false; if(!is_hex(k,128))return false; out[k]=x; }
    return true;
}
static bool parse_l2_tx(json_object*v,L2Transaction&t) {
    return v&&json_object_is_type(v,json_type_object)&&json_get_string(v,"sender_pubkey",t.sender_pubkey)&&json_get_string(v,"recipient",t.recipient)&&json_get_string(v,"signature",t.signature)&&json_get_string(v,"tx_id",t.tx_id)&&json_get_i64(v,"amount",t.amount)&&json_get_i64(v,"nonce",t.nonce)&&json_get_i64(v,"timestamp",t.timestamp);
}
static std::string l2_state_root(const std::map<std::string,i64>&balances,const std::map<std::string,i64>&nonces);
static std::string last_l2_state_root(const std::vector<Block>&prefix) {
    const std::map<std::string,i64> empty_b, empty_n;
    const std::string genesis=l2_state_root(empty_b,empty_n);
    for(auto bi=prefix.rbegin();bi!=prefix.rend();++bi) {
        for(auto ti=bi->transactions.rbegin();ti!=bi->transactions.rend();++ti) {
            json_object*o=json_tokener_parse(ti->c_str()); if(!o)continue; std::string typ,sr; bool ok=json_get_string(o,"type",typ)&&typ=="l2_commitment"&&json_get_string(o,"state_root",sr)&&is_hex(sr,128); json_object_put(o); if(ok)return sr;
        }
    }
    return genesis;
}

static bool commitment_has_withdrawal(json_object*commit,const std::string&claim_id,const std::string&recipient,i64 amount) {
    if(!commit) return false;
    json_object*arr=nullptr;
    if(!json_object_object_get_ex(commit,"withdrawals",&arr)||!arr||!json_object_is_type(arr,json_type_array)||json_object_array_length(arr)>MAX_L2_WITHDRAWALS_PER_BATCH)return false;
    for(size_t i=0;i<(size_t)json_object_array_length(arr);++i) {
        L2Withdrawal w;
        json_object*x=json_object_array_get_idx(arr,i);
        if(!parse_l2_withdrawal(x,w)) return false;
        if(w.claim_id==claim_id && w.l2_recipient==recipient && w.amount==amount) return true;
    }
    return false;
}
static bool prior_release_exists(const std::vector<Block>&prefix,const std::string&claim_id) {
    for(const auto&b:prefix) for(const auto&raw:b.transactions) {
        json_object*o=json_tokener_parse(raw.c_str()); if(!o) continue;
        std::string type,claim;
        bool ok=json_get_string(o,"type",type)&&type=="l2_withdrawal_release"&&json_get_string(o,"claim_id",claim)&&claim==claim_id;
        json_object_put(o); if(ok) return true;
    }
    return false;
}
static bool find_finalized_withdrawal(const std::vector<Block>&prefix,const std::string&commitment_hash,const std::string&claim_id,const std::string&recipient,i64 amount) {
    for(const auto&b:prefix) if(b.block_hash==commitment_hash) {
        if((int)prefix.size()-1-b.index < BRIDGE_FINALITY_DEPTH) return false;
        for(const auto&raw:b.transactions) {
            json_object*o=json_tokener_parse(raw.c_str()); if(!o) continue;
            std::string type; bool ok=json_get_string(o,"type",type)&&type=="l2_commitment"&&commitment_has_withdrawal(o,claim_id,recipient,amount);
            if(ok) { json_object_put(o); return true; }
            json_object_put(o);
        }
    }
    return false;
}

static bool find_finalized_deposit(const std::vector<Block>&prefix,const L2Deposit&d) {
    for(const auto&b:prefix) if(b.block_hash==d.l1_block_hash) {
        if((int)prefix.size()-1-b.index < BRIDGE_FINALITY_DEPTH) return false;
        for(const auto&raw:b.transactions) {
            json_object*o=json_tokener_parse(raw.c_str()); if(!o) continue;
            std::string typ,id,recipient; i64 amount=0;
            bool ok=json_get_string(o,"type",typ)&&typ=="transfer"&&json_get_string(o,"tx_id",id)&&id==d.l1_tx_id&&json_get_string(o,"recipient",recipient)&&recipient==L2_BRIDGE_ADDRESS&&json_get_i64(o,"amount",amount);
            Transaction q;
            if(ok) ok=json_get_string(o,"sender_pubkey",q.sender_pubkey)&&json_get_string(o,"recipient",q.recipient)&&json_get_i64(o,"amount",q.amount)&&json_get_i64(o,"nonce",q.nonce)&&json_get_i64(o,"timestamp",q.timestamp)&&json_get_string(o,"signature",q.signature)&&json_get_string(o,"tx_id",q.tx_id)&&q.valid(b.timestamp,true)&&q.net_amount()==d.amount;
            json_object_put(o); if(ok) return true;
        }
    }
    return false;
}
static bool verify_l2_deposit_manifest(json_object*o,const std::vector<Block>&prefix) {
    json_object*da=nullptr;
    if(!json_object_object_get_ex(o,"deposits",&da)||!da||!json_object_is_type(da,json_type_array)||json_object_array_length(da)>MAX_L2_DEPOSITS_PER_BATCH)return false;
    std::set<std::string>seen;
    for(size_t i=0;i<(size_t)json_object_array_length(da);++i) {
        L2Deposit d;
        if(!parse_l2_deposit(json_object_array_get_idx(da,i),d)||!seen.insert(d.claim_id).second||prior_release_exists(prefix,d.claim_id)||!find_finalized_deposit(prefix,d))return false;
    }
    return true;
}
static bool verify_l2_commitment(json_object*o,const std::string&expected_prev_root) {
    if(!o)return false;
    std::string type,prev_root,poh_prev,poh,state_root,root,commit_id; i64 count=0,first=0,last=0;
    if(!json_get_string(o,"type",type)||type!="l2_commitment"||!json_get_string(o,"prev_state_root",prev_root)||prev_root!=expected_prev_root||
       !json_get_string(o,"poh_prev",poh_prev)||!is_hex(poh_prev,128)||!json_get_string(o,"poh",poh)||!is_hex(poh,128)||
       !json_get_string(o,"state_root",state_root)||!is_hex(state_root,128)||!json_get_string(o,"root",root)||!is_hex(root,128)||
       !json_get_string(o,"tx_id",commit_id)||!is_hex(commit_id,128)||!json_get_i64(o,"count",count)||!json_get_i64(o,"first_sequence",first)||!json_get_i64(o,"last_sequence",last))return false;
    if(count<0||count>(i64)MAX_L2_TX_PER_BATCH)return false;
    if(count>0) { if(first<=0||last<first||last-first+1!=count)return false; }
    else { if(first!=last+1) return false; }
    json_object*arr=nullptr; if(!json_object_object_get_ex(o,"txs",&arr)||!json_object_is_type(arr,json_type_array)||(size_t)json_object_array_length(arr)!=(size_t)count)return false;
    json_object*darr=nullptr;
    if(!json_object_object_get_ex(o,"deposits",&darr)||!darr||!json_object_is_type(darr,json_type_array)||json_object_array_length(darr)>MAX_L2_DEPOSITS_PER_BATCH)return false;
    std::set<std::string>deposit_ids;
    for(size_t di=0;di<(size_t)json_object_array_length(darr);++di) {
        L2Deposit d; if(!parse_l2_deposit(json_object_array_get_idx(darr,di),d)||!deposit_ids.insert(d.claim_id).second)return false;
    }

    std::map<std::string,i64> pre_b,pre_n,post_b=pre_b,post_n=pre_n;
    if(!parse_l2_map(o,"pre_balances",pre_b)||!parse_l2_map(o,"pre_nonces",pre_n))return false;
    post_b=pre_b; post_n=pre_n;
    for(size_t di=0;di<(size_t)json_object_array_length(darr);++di) {
        L2Deposit d; if(!parse_l2_deposit(json_object_array_get_idx(darr,di),d))return false;
        if(post_b[d.l2_recipient]<0||post_b[d.l2_recipient]>MAX_SUPPLY-d.amount)return false;
        post_b[d.l2_recipient]+=d.amount;
    }
    std::string poh_cur=poh_prev; std::vector<std::string>ids; ids.reserve((size_t)count); std::vector<std::string>tx_jsons; tx_jsons.reserve((size_t)count);
    for(i64 i=0;i<count;i++) {
        L2Transaction t; if(!parse_l2_tx(json_object_array_get_idx(arr,(size_t)i),t)||!t.valid()||t.nonce<0||t.amount<=0||t.amount>MAX_SUPPLY)return false;
        tx_jsons.push_back(t.json());
        std::string sender=sha3_512(std::string((char*)unhex(t.sender_pubkey).data(),unhex(t.sender_pubkey).size()));
        i64 expected_nonce=post_n[sender]; i64 bal=post_b[sender]; if(t.nonce!=expected_nonce||bal<t.amount)return false;
        if(post_n[sender]==std::numeric_limits<i64>::max())return false;
        i64 rb=post_b[t.recipient]; if(rb<0||rb>MAX_SUPPLY-t.amount)return false;
        post_b[sender]=bal-t.amount; post_b[t.recipient]=rb+t.amount; post_n[sender]++;
        ids.push_back(t.tx_id); poh_cur=sha3_512(poh_cur+t.tx_id);
    }
    json_object*warr=nullptr;
    if(!json_object_object_get_ex(o,"withdrawals",&warr)||!warr||!json_object_is_type(warr,json_type_array)||json_object_array_length(warr)>MAX_L2_WITHDRAWALS_PER_BATCH)return false;
    std::set<std::string>withdraw_ids;
    for(size_t wi=0;wi<(size_t)json_object_array_length(warr);++wi) {
        L2Withdrawal w; if(!parse_l2_withdrawal(json_object_array_get_idx(warr,wi),w)||!withdraw_ids.insert(w.claim_id).second)return false;
        if(post_b[w.l2_recipient]<w.amount)return false;
        post_b[w.l2_recipient]-=w.amount;
        poh_cur=sha3_512(poh_cur+w.l2_tx_id);
    }
    if(merkle(ids)!=root||poh_cur!=poh||l2_state_root(post_b,post_n)!=state_root)return false;
    std::ostringstream prebo,preno; prebo<<"{"; bool pf=true; for(auto&[a,v]:pre_b){if(!pf)prebo<<",";pf=false;prebo<<json_escape(a)<<":"<<v;} prebo<<"}"; preno<<"{"; pf=true; for(auto&[a,v]:pre_n){if(!pf)preno<<",";pf=false;preno<<json_escape(a)<<":"<<v;} preno<<"}";
    std::ostringstream txs; txs<<"["; for(size_t i=0;i<tx_jsons.size();++i){if(i)txs<<",";txs<<tx_jsons[i];} txs<<"]";
    std::ostringstream deps; deps<<"["; for(size_t i=0;i<(size_t)json_object_array_length(darr);++i){if(i)deps<<",";L2Deposit d; if(!parse_l2_deposit(json_object_array_get_idx(darr,i),d))return false; deps<<d.json();} deps<<"]";
    std::ostringstream wds; wds<<"["; for(size_t i=0;i<(size_t)json_object_array_length(warr);++i){if(i)wds<<",";L2Withdrawal w; if(!parse_l2_withdrawal(json_object_array_get_idx(warr,i),w))return false; wds<<w.json();} wds<<"]";
    std::string canonical_commit=canonical({{"count",std::to_string(count)}, {"deposits",deps.str()}, {"first_sequence",std::to_string(first)}, {"last_sequence",std::to_string(last)}, {"poh",json_escape(poh)}, {"poh_prev",json_escape(poh_prev)}, {"pre_balances",prebo.str()}, {"pre_nonces",preno.str()}, {"prev_state_root",json_escape(prev_root)}, {"root",json_escape(root)}, {"state_root",json_escape(state_root)}, {"txs",txs.str()}, {"type",json_escape("l2_commitment")}, {"withdrawals",wds.str()}});
    return sha3_512(canonical_commit)==commit_id;
}
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
    std::string batch_pre_poh; u64 batch_first_sequence=0;
    bool deposit(const std::string&a,i64 x) { if(!is_hex(a,128)||x<=0||x>MAX_SUPPLY)return false; if(balances[a]<0||balances[a]>MAX_SUPPLY-x)return false; balances[a]+=x; return true; }
    bool claim_l1_deposit(const L2Deposit&d,const std::vector<Block>&l1_chain) {
        if(d.amount<=0||d.amount>MAX_SUPPLY||!is_hex(d.l1_tx_id,128)||!is_hex(d.l1_block_hash,128)||!is_hex(d.l2_recipient,128)||d.claim_id!=bridge_claim_id(d)) return false;
        if(spent_deposit_claims.count(d.claim_id)) return false;
        for(const auto&b:l1_chain) if(b.block_hash==d.l1_block_hash) {
            for(const auto&raw:b.transactions) {
                json_object*o=json_tokener_parse(raw.c_str()); if(!o)continue;
                std::string typ,id,recipient; i64 amount=0;
                bool ok=json_get_string(o,"type",typ)&&typ=="transfer"&&json_get_string(o,"tx_id",id)&&id==d.l1_tx_id&&json_get_string(o,"recipient",recipient)&&recipient==L2_BRIDGE_ADDRESS&&json_get_i64(o,"amount",amount);
                Transaction q;
                if(ok) ok=json_get_string(o,"sender_pubkey",q.sender_pubkey)&&json_get_string(o,"recipient",q.recipient)&&json_get_i64(o,"amount",q.amount)&&json_get_i64(o,"nonce",q.nonce)&&json_get_i64(o,"timestamp",q.timestamp)&&json_get_string(o,"signature",q.signature)&&json_get_string(o,"tx_id",q.tx_id)&&q.valid(b.timestamp,true)&&q.net_amount()==d.amount;
                json_object_put(o);
                if(ok) {
                    if(mempool.empty() && batch_deposits.empty() && batch_withdrawals.empty()) { batch_pre_balances=balances; batch_pre_nonces=nonces; batch_pre_poh=poh; batch_first_sequence=sequence+1; }
                    if(!deposit(d.l2_recipient,d.amount)) return false;
                    spent_deposit_claims.insert(d.claim_id); batch_deposits.push_back(d); return true;
                }
            }
        }
        return false;
    }
    bool request_withdrawal(const std::string&recipient,i64 x) {
        if(!is_hex(recipient,128)||x<=0||x>MAX_SUPPLY)return false;
        if(balances[recipient]<x)return false;
        if(batch_withdrawals.size()>=MAX_L2_WITHDRAWALS_PER_BATCH)return false;
        if(mempool.empty() && batch_withdrawals.empty()) { batch_pre_balances=balances; batch_pre_nonces=nonces; batch_pre_poh=poh; batch_first_sequence=sequence+1; }
        // Withdrawal burns/locks the L2 balance until an L1 release transaction is produced.
        balances[recipient]-=x;
        L2Withdrawal w; w.l2_recipient=recipient; w.amount=x;
        w.l2_tx_id=sha3_512(canonical({{"amount",std::to_string(x)}, {"recipient",json_escape(recipient)}, {"sequence",std::to_string(sequence)}, {"poh",json_escape(poh)}}));
        w.claim_id=withdrawal_claim_id(w);
        poh=sha3_512(poh+w.l2_tx_id); batch_withdrawals.push_back(w); return true;
    }

    bool add(const L2Transaction&t) {
        if(!t.valid()||t.amount<=0||t.amount>MAX_SUPPLY||t.nonce<0)return false;
        std::string sender=sha3_512(std::string((char*)unhex(t.sender_pubkey).data(),unhex(t.sender_pubkey).size()));
        if(mempool.empty()){batch_pre_balances=balances;batch_pre_nonces=nonces;batch_pre_poh=poh;batch_first_sequence=sequence+1;}
        if(t.nonce!=nonces[sender]||balances[sender]<t.amount)return false;
        if(nonces[sender]==std::numeric_limits<i64>::max())return false;
        if(balances[t.recipient]<0||balances[t.recipient]>MAX_SUPPLY-t.amount)return false;
        balances[sender]-=t.amount;balances[t.recipient]+=t.amount;nonces[sender]++;sequence++;poh=sha3_512(poh+t.tx_id);mempool.push_back(t);return mempool.size()<=MAX_L2_TX_PER_BATCH;
    }
    std::optional<std::string>commit() {
        if(mempool.empty() && batch_withdrawals.empty() && batch_deposits.empty())return std::nullopt;
        std::vector<std::string>ids;for(auto&t:mempool)ids.push_back(t.tx_id);
        std::string root=merkle(ids),state_root=l2_state_root(balances,nonces);std::ostringstream prebo,preno;prebo<<"{";bool f=true;for(auto&[a,v]:batch_pre_balances){if(!f)prebo<<",";f=false;prebo<<json_escape(a)<<":"<<v;}prebo<<"}";preno<<"{";f=true;for(auto&[a,v]:batch_pre_nonces){if(!f)preno<<",";f=false;preno<<json_escape(a)<<":"<<v;}preno<<"}";
        std::ostringstream txs;txs<<"[";for(size_t i=0;i<mempool.size();++i){if(i)txs<<",";txs<<mempool[i].json();}txs<<"]";
        std::ostringstream deps; deps<<"["; for(size_t i=0;i<batch_deposits.size();++i){if(i)deps<<",";deps<<batch_deposits[i].json();} deps<<"]";
        std::ostringstream wds; wds<<"["; for(size_t i=0;i<batch_withdrawals.size();++i){if(i)wds<<",";wds<<batch_withdrawals[i].json();} wds<<"]";
        std::string c=canonical({{"count",std::to_string(mempool.size())}, {"deposits",deps.str()}, {"first_sequence",std::to_string(batch_first_sequence)}, {"last_sequence",std::to_string(sequence)}, {"poh",json_escape(poh)}, {"poh_prev",json_escape(batch_pre_poh)}, {"pre_balances",prebo.str()}, {"pre_nonces",preno.str()}, {"prev_state_root",json_escape(l2_state_root(batch_pre_balances,batch_pre_nonces))}, {"root",json_escape(root)}, {"state_root",json_escape(state_root)}, {"txs",txs.str()}, {"type",json_escape("l2_commitment")}, {"withdrawals",wds.str()}});
        std::string id=sha3_512(c),out=c.substr(0,c.size()-1)+",\"tx_id\":"+json_escape(id)+"}";commitments.push_back(out);mempool.clear();batch_pre_balances.clear();batch_pre_nonces.clear();batch_pre_poh.clear();batch_first_sequence=0;batch_deposits.clear();batch_withdrawals.clear();return out;
    }
};
class SeenSet {
    size_t cap;
    std::set<std::string>s;
    std::deque<std::string>q;
    public:explicit SeenSet(size_t c):cap(c) {
    }
    bool contains(const std::string&x) {
        return s.count(x);
    }
    void add(const std::string&x) {
        if(s.count(x))return;
        s.insert(x);
        q.push_back(x);
        if(q.size()>cap) {
            s.erase(q.front());
            q.pop_front();
        }
    }
};
static bool send_all(int fd,const char*p,size_t n) {
    while(n) {
        ssize_t r=send(fd,p,n,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}
static bool recv_all(int fd,char*p,size_t n) {
    while(n) {
        ssize_t r=recv(fd,p,n,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}
static bool send_frame(int fd,const std::string&s) {
    if(s.size()>MAX_FRAME_BYTES)return false;
    uint32_t n=htonl((uint32_t)s.size());
    return send_all(fd,(char*)&n,4)&&send_all(fd,s.data(),s.size());
}
static std::optional<std::string> recv_frame(int fd) {
    uint32_t n=0;
    if(!recv_all(fd,(char*)&n,4))return std::nullopt;
    n=ntohl(n);
    if(n==0||n>MAX_FRAME_BYTES)return std::nullopt;
    std::string s(n,'\0');
    if(!recv_all(fd,s.data(),n))return std::nullopt;
    return s;
}

class P2PNode {
    Blockchain&bc; int listen_port=0; std::string peer_host; int peer_port=0; std::atomic<bool>stop{false}; int server_fd=-1;
    std::mutex peers_mu;
    std::map<std::string,std::pair<std::string,int>> peers;
    static constexpr size_t MAX_BLOCKS_RESPONSE=128;
    static bool valid_hello(json_object*o) {
        std::string net; int pv=0,ppv=0;
        return json_get_string(o,"network_id",net)&&json_get_int(o,"protocol_version",pv)&&json_get_int(o,"p2p_version",ppv)&&net==NETWORK_ID&&pv==PROTOCOL_VERSION&&ppv==P2P_PROTOCOL_VERSION;
    }
    static std::string msg(const std::string&type,const std::string&payload="") { return payload.empty()?"{\"type\":"+json_escape(type)+"}":"{\"type\":"+json_escape(type)+",\"payload\":"+json_escape(payload)+"}"; }
    static std::string msg_num(const std::string&type,const std::string&payload) { return "{\"type\":"+json_escape(type)+",\"payload\":"+payload+"}"; }
    void remember_peer(const std::string&host,int port) {
        if(port<1||port>65535||host.empty())return;
        std::lock_guard<std::mutex>g(peers_mu);
        std::string k=host+":"+std::to_string(port);
        if(peers.size()<MAX_PEERS||peers.count(k)) peers[k]={host,port};
    }
    bool send_blocks(int fd,size_t start) {
        auto c=bc.snapshot_from(start,MAX_BLOCKS_RESPONSE);
        std::string cj=chain_json(c);
        if(cj.empty()) return send_frame(fd,msg("error","blocks_too_large"));
        return send_frame(fd,msg("blocks",cj));
    }
    void handle(int fd,std::string remote_host,int remote_port) {
        timeval tv{P2P_HANDSHAKE_TIMEOUT_SEC,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        auto h=recv_frame(fd); if(!h)return; json_object*ho=json_tokener_parse(h->c_str()); if(!ho||!valid_hello(ho)){if(ho)json_object_put(ho);return;} json_object_put(ho);
        remember_peer(remote_host,remote_port);
        std::string hello="{\"type\":\"hello\",\"network_id\":"+json_escape(NETWORK_ID)+",\"protocol_version\":"+std::to_string(PROTOCOL_VERSION)+",\"p2p_version\":"+std::to_string(P2P_PROTOCOL_VERSION)+"}";
        if(!send_frame(fd,hello))return;
        tv={P2P_IDLE_TIMEOUT_SEC,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
        for(;;){auto fr=recv_frame(fd); if(!fr)break; json_object*o=json_tokener_parse(fr->c_str()); if(!o||!json_object_is_type(o,json_type_object)){if(o)json_object_put(o);break;}
            std::string type,payload; json_get_string(o,"type",type); json_get_string(o,"payload",payload);
            json_object*po=nullptr; size_t start=0;
            if(json_object_object_get_ex(o,"start",&po)&&json_object_is_type(po,json_type_int)){i64 v=json_object_get_int64(po); if(v>=0)start=(size_t)v;}
            json_object_put(o);
            if(type=="gettip") { auto c=bc.snapshot_chain(); if(!send_frame(fd,msg("tip",c.back().json())))break; }
            else if(type=="getheaders") {
                auto c=bc.snapshot_chain(); std::ostringstream out; out<<"["; size_t from=std::min(start,c.size()); size_t end=std::min(c.size(),from+MAX_BLOCKS_RESPONSE); for(size_t i=from;i<end;i++){if(i>from)out<<','; out<<c[i].block_hash;} out<<"]"; if(!send_frame(fd,msg("headers",out.str())))break;
            }
            else if(type=="getblocks") { if(!send_blocks(fd,start))break; }
            else if(type=="getchain") { auto c=bc.snapshot_chain(); std::string cj=chain_json(c); if(cj.empty()){send_frame(fd,msg("error","chain_too_large"));break;} if(!send_frame(fd,msg("chain",cj)))break; }
            else if(type=="ping") { if(!send_frame(fd,msg("pong")))break; }
            else if(type=="submitblock") { Block b; bool ok=parse_block(payload,b)&&bc.accept_block(b); if(!send_frame(fd,msg(ok?"accepted":"rejected")))break; }
            else if(type=="bye") break;
            else { if(!send_frame(fd,msg("error","unknown_message")))break; }
        }
    }
    int connect_peer() {
        addrinfo hints{},*res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
        std::string ps=std::to_string(peer_port); if(getaddrinfo(peer_host.c_str(),ps.c_str(),&hints,&res)!=0)return -1;
        int fd=-1; for(addrinfo*r=res;r;r=r->ai_next){fd=socket(r->ai_family,r->ai_socktype,r->ai_protocol); if(fd<0)continue; if(connect(fd,r->ai_addr,r->ai_addrlen)==0)break; close(fd);fd=-1;} freeaddrinfo(res); return fd;
    }
    bool handshake(int fd) {
        std::string h="{\"type\":\"hello\",\"network_id\":"+json_escape(NETWORK_ID)+",\"protocol_version\":"+std::to_string(PROTOCOL_VERSION)+",\"p2p_version\":"+std::to_string(P2P_PROTOCOL_VERSION)+"}";
        if(!send_frame(fd,h)) return false;
        auto r=recv_frame(fd); if(!r)return false;
        json_object*o=json_tokener_parse(r->c_str()); bool ok=false;
        if(o){
            std::string type,net; int pv=0,ppv=0;
            ok=json_get_string(o,"type",type)&&type=="hello"&&json_get_string(o,"network_id",net)&&json_get_int(o,"protocol_version",pv)&&json_get_int(o,"p2p_version",ppv)&&net==NETWORK_ID&&pv==PROTOCOL_VERSION&&ppv==P2P_PROTOCOL_VERSION;
            json_object_put(o);
        }
        return ok;
    }
    bool request_range(int fd,size_t start,std::vector<Block>&out) {
        std::string req="{\"type\":\"getblocks\",\"start\":"+std::to_string(start)+"}"; if(!send_frame(fd,req))return false; auto r=recv_frame(fd);if(!r)return false;json_object*o=json_tokener_parse(r->c_str());if(!o)return false;std::string type,payload;json_get_string(o,"type",type);json_get_string(o,"payload",payload);json_object_put(o);if(type!="blocks")return false;std::vector<Block>v;if(!parse_chain(payload,v))return false;out.insert(out.end(),v.begin(),v.end());return true;
    }
    void sync_once() {
        int fd=connect_peer(); if(fd<0)return; timeval tv{P2P_HANDSHAKE_TIMEOUT_SEC,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        if(!handshake(fd)){close(fd);return;} auto local=bc.snapshot_chain(); size_t start=local.size(); std::vector<Block>remote;
        while(true){std::vector<Block>chunk;if(!request_range(fd,start,chunk))break;if(chunk.empty())break;remote.insert(remote.end(),chunk.begin(),chunk.end());start+=chunk.size();if(chunk.size()<MAX_BLOCKS_RESPONSE)break;}
        if(!remote.empty()) { std::vector<Block>candidate=local; if(remote.front().index==static_cast<int>(candidate.size()))candidate.insert(candidate.end(),remote.begin(),remote.end()); else { candidate.clear(); std::vector<Block>tmp; size_t pos=0; while(true){std::vector<Block>ch;if(!request_range(fd,pos,ch))break;if(ch.empty())break;tmp.insert(tmp.end(),ch.begin(),ch.end());pos+=ch.size();if(ch.size()<MAX_BLOCKS_RESPONSE)break;} if(!tmp.empty())candidate=std::move(tmp); } bc.replace_chain(candidate); }
        send_frame(fd,msg("bye"));close(fd);
    }
public:
    P2PNode(Blockchain&b,int lp):bc(b),listen_port(lp){}
    P2PNode(Blockchain&b,const std::string&h,int p):bc(b),peer_host(h),peer_port(p){}
    void serve() {
        server_fd=socket(AF_INET,SOCK_STREAM,0); if(server_fd<0)throw std::runtime_error("P2P socket failed"); int one=1; setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons((uint16_t)listen_port); if(bind(server_fd,(sockaddr*)&a,sizeof(a))<0||listen(server_fd,MAX_PEERS)<0){close(server_fd);server_fd=-1;throw std::runtime_error("P2P bind/listen failed");}
        std::cout<<"[P2P] listening on 0.0.0.0:"<<listen_port<<"\n";
        while(!stop){sockaddr_storage ss{};socklen_t n=sizeof(ss);int fd=accept(server_fd,(sockaddr*)&ss,&n);if(fd<0){if(errno==EINTR)continue;break;}std::string rh="peer";int rp=0;if(ss.ss_family==AF_INET){auto*a=(sockaddr_in*)&ss;char buf[INET_ADDRSTRLEN];if(inet_ntop(AF_INET,&a->sin_addr,buf,sizeof(buf)))rh=buf;rp=ntohs(a->sin_port);}std::thread([this,fd,rh,rp]{handle(fd,rh,rp);close(fd);}).detach();}
    }
    void sync_loop(){while(!stop){sync_once();for(int i=0;i<15&&!stop;++i)std::this_thread::sleep_for(std::chrono::seconds(1));}}
};


static std::string withdrawal_release_id_fields(const std::string&commitment_hash,const std::string&recipient,const std::string&claim,i64 amount) { return sha3_512(canonical({{"amount",std::to_string(amount)}, {"claim_id",json_escape(claim)}, {"commitment_hash",json_escape(commitment_hash)}, {"recipient",json_escape(recipient)}, {"type",json_escape("l2_withdrawal_release")}})); }
static std::string withdrawal_release_id(const std::string&commitment_hash,const L2Withdrawal&w) { return withdrawal_release_id_fields(commitment_hash,w.l2_recipient,w.claim_id,w.amount); }
static std::string make_l2_withdrawal_release(const std::string&commitment_hash,const L2Withdrawal&w) {
    if(!is_hex(commitment_hash,128)||!is_hex(w.l2_recipient,128)||!is_hex(w.claim_id,128)||w.amount<=0||w.amount>MAX_SUPPLY||w.claim_id!=withdrawal_claim_id(w)) throw std::runtime_error("invalid L2 withdrawal release");
    return canonical({{"amount",std::to_string(w.amount)}, {"claim_id",json_escape(w.claim_id)}, {"commitment_hash",json_escape(commitment_hash)}, {"recipient",json_escape(w.l2_recipient)}, {"tx_id",json_escape(withdrawal_release_id(commitment_hash,w))}, {"type",json_escape("l2_withdrawal_release")}});
}
static Transaction make_transfer(const Wallet&w,const std::string&to,i64 em,i64 nonce) {
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
static MiningShare make_share(const std::string&m,const std::string&job,int d,u64 n) {
    MiningShare s;
    s.miner=m;
    s.job_id=job;
    s.difficulty=d;
    s.nonce=n;
    s.share_hash=s.calc_hash();
    s.share_id=s.calc_id();
    return s;
}
static void vector_test() {
    std::string miner(128,'a'),job(128,'b');
    MiningShare sh=make_share(miner,job,1,12345);
    Wallet pq;
    std::string pqmsg="EM_V19_PQ_VECTOR_MESSAGE";
    std::string pqsig=pq.sign(pqmsg);
    std::cout<<"PQ_PUB "<<pq.public_key_hex<<"\nPQ_ADDR "<<pq.address<<"\nPQ_MSG "<<pqmsg<<"\nPQ_SIG "<<pqsig<<"\nGEN_TX "<<hash_obj( {
         {
            "amount",std::to_string(BASE_REWARD)
        }
        ,  {
            "message",json_escape(GENESIS_MESSAGE)
        }
        ,  {
            "recipient",json_escape("Miner_Genesis")
        }
    }
    )<<"\n";
    std::cout<<"REWARD "<<hash_obj( {
         {
            "amount",std::to_string(INITIAL_BLOCK_REWARD)
        }
        ,  {
            "block_index","1"
        }
        ,  {
            "issuance",std::to_string(INITIAL_BLOCK_REWARD)
        }
        ,  {
            "recipient",json_escape(miner)
        }
        ,  {
            "type",json_escape("reward")
        }
    }
    )<<"\n";
    std::cout<<"SHARE_CHAL "<<sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+job+"-1")<<"\n";
    std::cout<<"SHARE_HASH "<<sh.share_hash<<"\n";
    std::cout<<"SHARE_ID "<<sh.share_id<<"\n";
    std::cout<<"SHARE_WORK "<<block_work(1)<<"\n";
    std::map<std::string,i64> vb {
         {
            std::string(128,'a'),987654321
        }
        , {
            std::string(128,'b'),123456789
        }
    };
    std::map<std::string,i64> vn {
         {
            std::string(128,'a'),7
        }
        , {
            std::string(128,'b'),2
        }
    };
    std::ostringstream bo,no;
    bo<<"{";
     {
        bool f=true;
        for(auto&[a,v]:vb) {
            if(!f)bo<<",";
            f=false;
            bo<<json_escape(a)<<":"<<v;
        }
    }
    bo<<"}";
    no<<"{";
     {
        bool f=true;
        for(auto&[a,v]:vn) {
            if(!f)no<<",";
            f=false;
            no<<json_escape(a)<<":"<<v;
        }
    }
    no<<"}";
    std::string sr=hash_obj( {
         {
            "balances",bo.str()
        }
        , {
            "nonces",no.str()
        }
    }
    );
    std::cout<<"STATE_ROOT "<<sr<<"\n";
    std::cout<<"COMMIT_ID "<<hash_obj( {
         {
            "count","2"
        }
        , {
            "first_sequence","1"
        }
        , {
            "last_sequence","2"
        }
        , {
            "root",json_escape(std::string(128,'c'))
        }
        , {
            "state_root",json_escape(sr)
        }
        , {
            "type",json_escape("l2_commitment")
        }
    }
    )<<"\n";
    std::filesystem::path d=std::filesystem::temp_directory_path()/"em_v18_vectors.json";
    std::error_code ec;
    std::filesystem::remove(d,ec);
    Blockchain bc(d.string());
    auto &g=bc.chain[0];
    std::cout<<"GEN_NONCE "<<g.nonce<<"\nGEN_HASH "<<g.block_hash<<"\nGEN_MERKLE "<<g.merkle_root<<"\n";
    std::filesystem::remove(d,ec);
}
static void make_fixture(const std::string&path) {
    std::error_code ec;
    std::filesystem::remove(path,ec);
    Blockchain bc(path);
    Wallet a,b;
    bc.mine_pending(a.address);
    auto tx=make_transfer(a,b.address,1,bc.next_nonce(a.address));
    if(!bc.add_transaction(tx))throw std::runtime_error("fixture tx admission failed");
    bc.mine_pending(b.address);
    if(!bc.validate_chain(bc.chain))throw std::runtime_error("fixture chain invalid");
    std::cout<<"FIXTURE_VALID height="<<bc.height()<<" work="<<bc.cumulative_work().convert_to<std::string>()<<" supply="<<bc.supply()<<"\n";
}
static void self_test() {
    std::cout<<"[SELF-TEST] creating ML-DSA-65 wallets...\n";
    Wallet a,b,m;
    Transaction p=make_transfer(a,a.address,1,0);
    if(p.signature.size()!=Wallet::SIG_HEX||!p.valid())throw std::runtime_error("PQ signature test failed");
    if(subsidy(1)!=INITIAL_BLOCK_REWARD||subsidy(HALVING_INTERVAL)!=INITIAL_BLOCK_REWARD/2)throw std::runtime_error("halving failed");
    std::filesystem::path d=std::filesystem::temp_directory_path()/"em_v18_test.json";
    std::error_code ec;
    std::filesystem::remove(d,ec);
    Blockchain bc(d.string());
    auto bl=bc.mine_pending(a.address);
    if(bl.index!=1||bc.balances[a.address]!=BASE_REWARD)throw std::runtime_error("mining failed");
    auto t=make_transfer(a,b.address,10,bc.next_nonce(a.address));
    if(!bc.add_transaction(t))throw std::runtime_error("tx admission failed");
    bc.mine_pending(m.address);
    i64 tt=(10*COIN*RECEIVER_TAX_BPS)/10000,bb=(10*COIN*TX_BURN_BPS)/10000;
    if(bc.balances[b.address]!=10*COIN-tt-bb||bc.total_burned<bb||bc.treasury_balance<tt)throw std::runtime_error("fee/burn failed");
    if(!bc.validate_chain(bc.chain))throw std::runtime_error("replay failed");
    if(bc.wallet_anchor["Miner_Genesis"]!=bc.chain[1].timestamp)throw std::runtime_error("genesis tax anchor initialization failed");
    // Regression test: an immediate first block must not charge the Genesis wallet.
    if(bc.treasury_balance>tt)throw std::runtime_error("unexpected genesis annual tax");

    // L2 regression: reject nonce overflow before mutating balances/state.
    Layer2Sequencer l2;
    std::string l2sender=sha3_512(std::string((char*)unhex(a.public_key_hex).data(),unhex(a.public_key_hex).size()));
    if(!is_hex(L2_BRIDGE_ADDRESS,128))throw std::runtime_error("invalid bridge address");
    L2Deposit dp; dp.amount=COIN; dp.l1_tx_id=sha3_512("deposit-tx"); dp.l1_block_hash=sha3_512("deposit-block"); dp.l2_recipient=l2sender; dp.claim_id=bridge_claim_id(dp);
    if(!parse_l2_deposit(json_tokener_parse(dp.json().c_str()),dp))throw std::runtime_error("deposit parser regression");
    if(!l2.deposit(l2sender,2*COIN))throw std::runtime_error("L2 deposit failed");
    L2Transaction ltx;
    ltx.sender_pubkey=a.public_key_hex;
    ltx.recipient=b.address;
    ltx.amount=COIN;
    ltx.nonce=0;
    ltx.timestamp=now_s();
    ltx.signature=a.sign(ltx.signing());
    ltx.tx_id=hash_obj({
        {"amount",std::to_string(ltx.amount)},
        {"nonce",std::to_string(ltx.nonce)},
        {"recipient",json_escape(ltx.recipient)},
        {"sender_pubkey",json_escape(ltx.sender_pubkey)},
        {"signature",json_escape(ltx.signature)},
        {"timestamp",std::to_string(ltx.timestamp)}
    });
    if(!l2.add(ltx))throw std::runtime_error("L2 transfer failed");
    i64 sender_before=l2.balances[l2sender], recipient_before=l2.balances[b.address];
    L2Transaction overflow=ltx;
    overflow.nonce=std::numeric_limits<i64>::max();
    overflow.signature=a.sign(overflow.signing());
    overflow.tx_id=hash_obj({
        {"amount",std::to_string(overflow.amount)},
        {"nonce",std::to_string(overflow.nonce)},
        {"recipient",json_escape(overflow.recipient)},
        {"sender_pubkey",json_escape(overflow.sender_pubkey)},
        {"signature",json_escape(overflow.signature)},
        {"timestamp",std::to_string(overflow.timestamp)}
    });
    if(l2.add(overflow) || l2.balances[l2sender]!=sender_before || l2.balances[b.address]!=recipient_before)
        throw std::runtime_error("L2 nonce overflow mutated state");
    // V19 regression: a committed L2 batch must be independently replayable.
    std::string l2_expected_prev=l2_state_root(l2.batch_pre_balances,l2.batch_pre_nonces);
    auto l2commit=l2.commit();
    if(!l2commit) throw std::runtime_error("L2 commitment creation failed");
    json_object*l2o=json_tokener_parse(l2commit->c_str());
    if(!l2o || !verify_l2_commitment(l2o,l2_expected_prev)) { if(l2o)json_object_put(l2o); throw std::runtime_error("L2 commitment verification failed"); }
    json_object_put(l2o);
    if(!l2.request_withdrawal(b.address,COIN/2))throw std::runtime_error("L2 withdrawal intent failed");
    std::string wd_prev=l2_state_root(l2.batch_pre_balances,l2.batch_pre_nonces);
    auto wdcommit=l2.commit();
    if(!wdcommit)throw std::runtime_error("L2 withdrawal commitment creation failed");
    json_object*wco=json_tokener_parse(wdcommit->c_str());
    if(!wco || !verify_l2_commitment(wco,wd_prev)) { if(wco)json_object_put(wco); throw std::runtime_error("L2 withdrawal transition verification failed"); }
    L2Withdrawal wd; wd.l2_recipient=b.address; wd.amount=COIN/2;
    json_object*wa=nullptr; if(!json_object_object_get_ex(wco,"withdrawals",&wa)||json_object_array_length(wa)!=1) { json_object_put(wco); throw std::runtime_error("withdrawal manifest missing"); }
    if(!parse_l2_withdrawal(json_object_array_get_idx(wa,0),wd)) { json_object_put(wco); throw std::runtime_error("withdrawal parser regression"); }
    json_object_put(wco);

    // V19.2 bridge regression: finalized L1 deposit -> L2 commitment ->
    // withdrawal commitment -> finalized release on L1, with replay protection.
    std::filesystem::path bd=std::filesystem::temp_directory_path()/"em_v19_bridge.json";
    std::filesystem::remove(bd,ec);
    Blockchain bridge(bd.string());
    Wallet ba, bm;
    bridge.mine_pending(ba.address);
    auto dep_tx=make_transfer(ba,L2_BRIDGE_ADDRESS,5,bridge.next_nonce(ba.address));
    if(!bridge.add_transaction(dep_tx))throw std::runtime_error("bridge deposit admission failed");
    auto dep_block=bridge.mine_pending(bm.address);
    for(int i=0;i<BRIDGE_FINALITY_DEPTH;i++) bridge.mine_pending(bm.address);
    Layer2Sequencer bl2;
    L2Deposit bdclaim; bdclaim.amount=dep_tx.net_amount(); bdclaim.l1_tx_id=dep_tx.tx_id; bdclaim.l1_block_hash=dep_block.block_hash; bdclaim.l2_recipient=ba.address; bdclaim.claim_id=bridge_claim_id(bdclaim);
    if(!bl2.claim_l1_deposit(bdclaim,bridge.chain))throw std::runtime_error("finalized L1 deposit claim failed");
    auto dep_commit=bl2.commit(); if(!dep_commit)throw std::runtime_error("deposit commitment failed");
    bridge.mine_external(bm.address,{*dep_commit});
    if(!bridge.validate_chain(bridge.chain))throw std::runtime_error("deposit commitment replay failed");
    if(!bl2.request_withdrawal(ba.address,COIN))throw std::runtime_error("bridge withdrawal request failed");
    auto wd2=bl2.commit(); if(!wd2)throw std::runtime_error("withdrawal commitment failed");
    json_object*wdobj=json_tokener_parse(wd2->c_str()); if(!wdobj)throw std::runtime_error("withdrawal commitment parse failed");
    json_object*wa2=nullptr; if(!json_object_object_get_ex(wdobj,"withdrawals",&wa2)||json_object_array_length(wa2)!=1){json_object_put(wdobj);throw std::runtime_error("withdrawal manifest invalid");}
    L2Withdrawal bw; if(!parse_l2_withdrawal(json_object_array_get_idx(wa2,0),bw)){json_object_put(wdobj);throw std::runtime_error("withdrawal parse failed");} json_object_put(wdobj);
    auto wd_block=bridge.mine_external(bm.address,{*wd2});
    for(int i=0;i<BRIDGE_FINALITY_DEPTH;i++) bridge.mine_pending(bm.address);
    i64 before_release=bridge.balances[ba.address];
    std::string rel=make_l2_withdrawal_release(wd_block.block_hash,bw);
    bridge.mine_external(bm.address,{rel});
    if(bridge.balances[ba.address]!=before_release+bw.amount)throw std::runtime_error("L1 withdrawal release failed");
    if(!bridge.validate_chain(bridge.chain))throw std::runtime_error("bridge replay failed");
    bool replay_rejected=false; try { bridge.mine_external(bm.address,{rel}); } catch(...) { replay_rejected=true; }
    if(!replay_rejected)throw std::runtime_error("withdrawal replay protection failed");
    std::filesystem::remove(bd,ec);

    // Persistence regression: pending transactions survive a clean restart.
    std::filesystem::path pd=std::filesystem::temp_directory_path()/"em_v19_pending.json";
    std::filesystem::remove(pd,ec);
    Blockchain pbc(pd.string());
    pbc.mine_pending(a.address);
    auto ptx=make_transfer(a,b.address,1,pbc.next_nonce(a.address));
    if(!pbc.add_transaction(ptx))throw std::runtime_error("persistence admission failed");
    { Blockchain pbc2(pd.string()); if(!pbc2.pending.count(ptx.tx_id))throw std::runtime_error("pending persistence failed"); }
    std::filesystem::remove(pd,ec);
    std::filesystem::remove(d,ec);
    std::cout<<"[SELF-TEST] all tests passed\n";
}
int main(int argc,char**argv) {
    try {
        bool test=false,vectors=false,mine=false,validate_db=false; int listen_port=0,peer_port=0; std::string peer_host;
        std::string make_fixture_path;
        std::string db="electric_money_v19.json";
        for(int i=1;i<argc;i++) {
            std::string a=argv[i];
            if(a=="--self-test")test=true;
            else if(a=="--vectors")vectors=true;
            else if(a=="--validate-db")validate_db=true;
            else if(a=="--make-fixture"&&i+1<argc)make_fixture_path=argv[++i];
            else if(a=="--verify-pq"&&i+3<argc) {
                std::string pub=argv[++i],msg=argv[++i],sig=argv[++i];
                bool ok=Wallet::verify(pub,msg,sig);
                std::cout<<(ok?"VERIFY_OK":"VERIFY_FAIL")<<"\n";
                return ok?0:1;
            } else if(a=="--mine")mine=true;
            else if(a=="--listen"&&i+1<argc)listen_port=std::stoi(argv[++i]);
            else if(a=="--connect"&&i+1<argc){std::string ep=argv[++i]; auto pos=ep.rfind(':'); if(pos==std::string::npos)throw std::runtime_error("--connect requires host:port"); peer_host=ep.substr(0,pos); peer_port=std::stoi(ep.substr(pos+1));}
            else if(a=="--db"&&i+1<argc)db=argv[++i];
        }
        if(vectors) {
            vector_test();
            return 0;
        }
        if(test) {
            self_test();
            return 0;
        }
        if(!make_fixture_path.empty()) {
            make_fixture(make_fixture_path);
            return 0;
        }
        Blockchain bc(db);
        if(listen_port>0 && (listen_port<1 || listen_port>65535))throw std::runtime_error("invalid listen port");
        if(peer_port>0 && (peer_port<1 || peer_port>65535))throw std::runtime_error("invalid peer port");
        if(validate_db) {
            std::cout<<"CHAIN_VALID height="<<bc.height()<<" work="<<bc.cumulative_work().convert_to<std::string>()<<" supply="<<bc.supply()<<"\n";
            return 0;
        }
        Wallet miner;
        std::cout<<"[NODE] miner address: "<<miner.address<<"\n";
        if(listen_port>0) { auto node=std::make_shared<P2PNode>(bc,listen_port); std::thread([node]{node->serve();}).detach(); }
        if(peer_port>0) { auto syncer=std::make_shared<P2PNode>(bc,peer_host,peer_port); std::thread([syncer]{syncer->sync_loop();}).detach(); }
        if(mine) {
            while(true) {
                Block b=bc.mine_pending(miner.address);
                std::cout<<"[MINER] block="<<b.index<<" difficulty="<<b.difficulty<<" work="<<bc.cumulative_work().convert_to<std::string>()<<"\n";
            }
        } else {
            std::cout<<"[NODE] height="<<bc.height()<<" supply="<<std::fixed<<std::setprecision(8)<<(double)bc.supply()/COIN<<" EM\n";
            for(;;)std::this_thread::sleep_for(std::chrono::minutes(1));
        }
    } catch(const std::exception&e) {
        std::cerr<<"fatal: "<<e.what()<<"\n";
        return 2;
    }
}

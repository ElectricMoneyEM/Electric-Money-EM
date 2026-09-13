#pragma once

#include <openssl/params.h>
#include <openssl/core_names.h>
#include <functional>
#include <cctype>
// Electric Money V19.2 Post-Quantum — C++17 consensus/reference port (verifiable L2/PoH bridge foundation)
// Derived from Electric Money V17.3 with stronger persistence, mempool recovery, and V18 protocol separation.
// NOT production/mainnet cryptocurrency software.
// Requires OpenSSL 3.5+ (ML-DSA-65) and json-c.
// Build is managed by CMake; OpenSSL 3.5+ and json-c are required.
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
i64 now_s();

std::string hex(const unsigned char*p,size_t n);

std::vector<unsigned char> unhex(const std::string&s);

std::string json_escape(const std::string&s);

std::string sha3_512(const std::string&s);

std::string canonical(const std::map<std::string,std::string>&raw);

std::string hash_obj(const std::map<std::string,std::string>&m);

bool is_hex(const std::string&s,size_t len);

bool json_get_string(json_object*o,const char*k,std::string&out);

bool json_get_i64(json_object*o,const char*k,i64&out);

bool json_get_u64(json_object*o,const char*k,u64&out);

bool json_get_int(json_object*o,const char*k,int&out);

i64 checked_amount(i64 x);


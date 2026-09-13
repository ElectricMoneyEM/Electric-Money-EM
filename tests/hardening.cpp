#include "em/electric_money.hpp"
#include <cassert>
#include <iostream>
#include <random>

static void assert_false_parse_block(const std::string& s){ Block b; assert(!parse_block(s,b)); }
static void assert_false_parse_chain(const std::string& s){ std::vector<Block> c; assert(!parse_chain(s,c)); }

int main(){
    // Parser robustness: malformed, truncated, oversized and wrong-type JSON must be rejected.
    assert_false_parse_block("");
    assert_false_parse_block("{}");
    assert_false_parse_block("[]");
    assert_false_parse_block("{not-json");
    assert_false_parse_chain("");
    assert_false_parse_chain("{}");
    assert_false_parse_chain("[]");
    std::string huge(MAX_BLOCK_BYTES + 1, 'x');
    assert_false_parse_block(huge);
    std::string huge_chain(MAX_CHAIN_SYNC_BYTES + 1, 'x');
    assert_false_parse_chain(huge_chain);

    // Deterministic parser fuzz smoke: arbitrary byte strings must never crash.
    std::mt19937_64 rng(0x454D205F323035ULL);
    for(int i=0;i<5000;i++){
        size_t n = rng()%2048;
        std::string x(n,'\0');
        for(char &c:x) c=static_cast<char>(rng() & 0xff);
        Block b; parse_block(x,b);
        std::vector<Block> c; parse_chain(x,c);
    }

    // Consensus arithmetic edge cases.
    assert(subsidy(1)==INITIAL_BLOCK_REWARD);
    assert(subsidy(HALVING_INTERVAL)==INITIAL_BLOCK_REWARD/2);
    assert(subsidy(HALVING_INTERVAL*2)==INITIAL_BLOCK_REWARD/4);
    assert(subsidy(1000000000)==0);
    assert(block_work(MIN_DIFFICULTY)>0);

    std::cout << "HARDENING_TESTS_PASS parser=5000 consensus=edge-cases\n";
}

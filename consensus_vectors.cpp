#include "em/electric_money.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>

static void must(bool x,const char* m){ if(!x) throw std::runtime_error(m); }

int main(){
    must(sha3_512("Electric Money") == "e0b8f0d9869ef6a19283a667ad07bbaefdf40d2cec0571a9eadd308a6c9307196ad7527e5e5b5f7478e9ba447b1f9ac7e9c705a9ec1bafcc99a952236a45a39f", "SHA3-512 vector mismatch");
    must(hash_obj({{"a","1"},{"b","2"}}) == hash_obj({{"b","2"},{"a","1"}}), "canonical map ordering mismatch");
    must(is_hex(ZERO_HASH,128), "zero hash invariant");

    // Subsidy schedule and cumulative-work domain.
    must(subsidy(1)==INITIAL_BLOCK_REWARD, "initial subsidy");
    must(subsidy(HALVING_INTERVAL)==INITIAL_BLOCK_REWARD/2, "first halving");
    must(subsidy(2*HALVING_INTERVAL)==INITIAL_BLOCK_REWARD/4, "second halving");
    must(subsidy(63*HALVING_INTERVAL)==0, "terminal subsidy");
    for(int d=MIN_DIFFICULTY; d<=MAX_DIFFICULTY; ++d) must(block_work(d)>0, "block work domain");

    // Transaction fee split is deterministic: 20 bps treasury + 5 bps burn.
    Wallet a,b;
    Transaction t=make_transfer(a,b.address,100,0);
    must(t.amount==100*COIN, "transfer amount");
    must(t.burned()==5*COIN/100, "burn split");
    must(t.receiver_tax()==20*COIN/100, "treasury split");
    must(t.net_amount()==100*COIN-t.burned()-t.receiver_tax(), "net amount");
    must(t.valid(), "generated transfer validity");

    // Genesis serialization/hash and round-trip parsing.
    std::filesystem::path p=std::filesystem::temp_directory_path()/"em_v20_7_vectors.json";
    std::error_code ec; std::filesystem::remove(p,ec);
    Blockchain bc(p.string());
    must(bc.chain.size()==1, "genesis chain size");
    must(bc.chain[0].index==0, "genesis index");
    must(bc.chain[0].block_hash=="00c5997a54747344d26e5f375e1cb95c2298c046003d85473e30486c2ac5cd0f630c8e31f0c64c8224401bbc9bef04cb91ab8a08d227d4d46c0bc2d844c8c4f0", "genesis hash");
    Block rb; must(parse_block(bc.chain[0].json(),rb), "block round-trip parse");
    must(rb.block_hash==bc.chain[0].block_hash, "block round-trip hash");
    std::vector<Block> rc; must(parse_chain(chain_json(bc.chain),rc), "chain round-trip parse");
    must(rc.size()==1 && rc[0].block_hash==bc.chain[0].block_hash, "chain round-trip equality");

    // L2 deterministic state root and claim identifiers.
    std::map<std::string,i64> bal{{std::string(128,'a'),987654321},{std::string(128,'b'),123456789}};
    std::map<std::string,i64> non{{std::string(128,'a'),7},{std::string(128,'b'),2}};
    std::string root=l2_state_root(bal,non);
    must(is_hex(root,128), "L2 state root format");
    L2Deposit d; d.amount=COIN; d.l1_tx_id=sha3_512("deposit-tx"); d.l1_block_hash=sha3_512("deposit-block"); d.l2_recipient=a.address; d.claim_id=bridge_claim_id(d);
    must(is_hex(d.claim_id,128), "deposit claim id");
    L2Withdrawal w; w.amount=COIN/2; w.l2_recipient=b.address; w.claim_id=withdrawal_claim_id(w);
    must(is_hex(w.claim_id,128), "withdrawal claim id");
    std::string rel=withdrawal_release_id_fields(sha3_512("commit"),w.l2_recipient,w.claim_id,w.amount);
    must(is_hex(rel,128), "release id");

    std::filesystem::remove(p,ec);
    std::cout<<"CONSENSUS_VECTORS_PASS modules=common,wallet,tx,mining,block,blockchain,l2,bridge\n";
}

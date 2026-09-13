#include "em/electric_money.hpp"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>

static void must(bool x,const char* m){ if(!x) throw std::runtime_error(m); }

int main(){
    const auto base=std::filesystem::temp_directory_path();
    const auto p1=(base/"em_v20_7_4_a.json").string();
    const auto p2=(base/"em_v20_7_4_b.json").string();
    std::error_code ec;
    std::filesystem::remove(p1,ec); std::filesystem::remove(p2,ec);

    // 1) State transition + persistence/reload.
    Blockchain a(p1);
    Wallet miner;
    Block a1=a.mine_external(miner.address,{});
    must(a.height()==1,"height after first block");
    const auto issued1=a.total_issued, burned1=a.total_burned, treas1=a.treasury_balance;
    const auto bal1=a.balances;
    const auto chain1=a.snapshot_chain();
    a.save();
    must(std::filesystem::exists(p1),"save state");
    Blockchain reloaded(p1);
    must(reloaded.validate_chain(reloaded.chain),"reloaded chain validation");
    must(reloaded.snapshot_chain().size()==chain1.size(),"reload chain size");
    must(reloaded.chain.back().block_hash==chain1.back().block_hash,"reload tip");
    must(reloaded.total_issued==issued1 && reloaded.total_burned==burned1 && reloaded.treasury_balance==treas1,"reload accounting");
    must(reloaded.balances==bal1,"reload balances");

    // 2) Deterministic chain-selection/reorg rule: strictly greater cumulative
    // work wins; equal/lower work is rejected.
    Blockchain b(p2);
    b.mine_external(miner.address,{});
    auto short_chain=b.snapshot_chain();
    must(a.cumulative_work()==b.cumulative_work(),"equal-work branches");
    must(!a.replace_chain(short_chain),"equal-work replacement rejected");

    b.mine_external(miner.address,{});
    auto longer=b.snapshot_chain();
    must(longer.size()==3,"longer branch height");
    must(Blockchain::cumulative(longer)>Blockchain::cumulative(chain1),"longer branch greater work");
    must(a.replace_chain(longer),"greater-work replacement accepted");
    must(a.chain.back().block_hash==longer.back().block_hash,"reorg tip selected");
    must(a.validate_chain(a.chain),"post-reorg chain validates");

    // 3) Tamper rejection: changing a transaction payload invalidates the
    // block/chain transcript and must not be accepted as a replacement.
    auto tampered=longer;
    tampered.back().extra_data += "-tampered";
    must(!a.replace_chain(tampered),"tampered chain rejected");

    // 4) Snapshot/range semantics used by P2P synchronization.
    auto s0=a.snapshot_from(0,2);
    auto s1=a.snapshot_from(2,2);
    must(s0.size()==2 && s1.size()==1,"snapshot ranges");
    must(s0[1].block_hash==a.chain[1].block_hash && s1[0].block_hash==a.chain[2].block_hash,"snapshot ordering");

    std::filesystem::remove(p1,ec); std::filesystem::remove(p2,ec);
    std::cout << "CONSENSUS_TRANSITION_PASS state=persistence,reload,reorg,work,tamper,snapshot\n";
}

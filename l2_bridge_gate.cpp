#include "em/electric_money.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
static void must(bool x,const char* m){if(!x)throw std::runtime_error(m);}
static json_object* parse(const std::string&s){return json_tokener_parse(s.c_str());}
int main(){
 std::filesystem::path p=std::filesystem::temp_directory_path()/"em_v20_7_5_l2.json"; std::error_code ec; std::filesystem::remove(p,ec);
 Blockchain bc(p.string()); Wallet user,miner;
 bc.mine_pending(user.address);
 auto dep=make_transfer(user,L2_BRIDGE_ADDRESS,5,bc.next_nonce(user.address));
 must(bc.add_transaction(dep),"deposit admission"); auto db=bc.mine_pending(miner.address);
 for(int i=0;i<BRIDGE_FINALITY_DEPTH;i++) bc.mine_pending(miner.address);
 L2Deposit d; d.l1_tx_id=dep.tx_id; d.l1_block_hash=db.block_hash; d.l2_recipient=user.address; d.amount=dep.net_amount(); d.claim_id=bridge_claim_id(d);
 Layer2Sequencer l2; must(l2.claim_l1_deposit(d,bc.chain),"finalized deposit");
 must(!l2.claim_l1_deposit(d,bc.chain),"duplicate deposit claim");
 auto c=l2.commit(); must(c.has_value(),"deposit commit");
 json_object*co=parse(*c); must(co&&verify_l2_commitment(co,last_l2_state_root(bc.chain)),"commit verifies");
 json_object_object_add(co,"state_root",json_object_new_string(std::string(128,'0').c_str()));
 must(!verify_l2_commitment(co,last_l2_state_root(bc.chain)),"tampered state root rejected"); json_object_put(co);
 bc.mine_external(miner.address,{*c}); must(bc.validate_chain(bc.chain),"L2 commit accepted");
 must(l2.request_withdrawal(user.address,COIN),"withdrawal request"); auto wc=l2.commit(); must(wc.has_value(),"withdrawal commit");
 json_object*wo=parse(*wc); must(wo,"withdrawal json"); json_object*wa=nullptr; must(json_object_object_get_ex(wo,"withdrawals",&wa)&&json_object_array_length(wa)==1,"withdrawal manifest");
 L2Withdrawal w; must(parse_l2_withdrawal(json_object_array_get_idx(wa,0),w),"withdrawal parse"); json_object_put(wo);
 auto wb=bc.mine_external(miner.address,{*wc});
 // Not finalized yet: release must be rejected.
 std::string early=make_l2_withdrawal_release(wb.block_hash,w);
 bool early_rejected=false; try{bc.mine_external(miner.address,{early});}catch(...){early_rejected=true;} must(early_rejected,"early release rejected");
 for(int i=0;i<BRIDGE_FINALITY_DEPTH;i++) bc.mine_pending(miner.address);
 std::string rel=make_l2_withdrawal_release(wb.block_hash,w); i64 before=bc.balances[user.address];
 bc.mine_external(miner.address,{rel}); must(bc.balances[user.address]==before+w.amount,"final release credited");
 bool replay=false; try{bc.mine_external(miner.address,{rel});}catch(...){replay=true;} must(replay,"release replay rejected");
 // Wrong release binding must not validate.
 L2Withdrawal wrong=w; wrong.amount+=1; wrong.claim_id=withdrawal_claim_id(wrong);
 std::string bad=make_l2_withdrawal_release(wb.block_hash,wrong); bool bad_rejected=false; try{bc.mine_external(miner.address,{bad});}catch(...){bad_rejected=true;} must(bad_rejected,"wrong amount release rejected");
 json_object*manifest=parse(*wc); must(manifest,"manifest parse"); json_object_object_add(manifest,"poh",json_object_new_string(std::string(128,'a').c_str())); must(!verify_l2_commitment(manifest,l2_state_root(l2.batch_pre_balances,l2.batch_pre_nonces)),"tampered PoH rejected"); json_object_put(manifest);
 std::filesystem::remove(p,ec); std::cout<<"L2_BRIDGE_GATE_PASS deposit_finality,commit_integrity,withdrawal_finality,replay,wrong_binding\n";
}

#include "em/app.hpp"


void consensus_gate() {
    // Deterministic consensus-only gate: no random PQ material and no real PoW mining.
    std::cout << "EM_GATE_VERSION V20.7.2\n";
    std::cout << "SHA3 " << sha3_512("Electric Money") << "\n";
    std::cout << "CANON " << hash_obj({{"a","1"},{"b","2"}}) << "\n";
    std::cout << "GEN_TX " << hash_obj({{"amount",std::to_string(BASE_REWARD)}, {"message",json_escape(GENESIS_MESSAGE)}, {"recipient",json_escape("Miner_Genesis")}}) << "\n";
    std::cout << "REWARD " << hash_obj({{"amount",std::to_string(INITIAL_BLOCK_REWARD)}, {"block_index","1"}, {"issuance",std::to_string(INITIAL_BLOCK_REWARD)}, {"recipient",std::string(128,'a')}, {"type",json_escape("reward")}}) << "\n";
    std::cout << "SHARE_CHAL " << sha3_512("ELECTRIC-MONEY-SHARE-"+NETWORK_ID+"-"+std::string(128,'b')+"-1") << "\n";
    MiningShare sh=make_share(std::string(128,'a'),std::string(128,'b'),1,12345);
    std::cout << "SHARE_HASH " << sh.share_hash << "\n";
    std::cout << "SHARE_ID " << sh.share_id << "\n";
    std::cout << "SHARE_WORK " << block_work(1) << "\n";
    for(int h : {1, HALVING_INTERVAL, 2*HALVING_INTERVAL, 63*HALVING_INTERVAL, 64*HALVING_INTERVAL, 1000000000})
        std::cout << "SUBSIDY " << h << " " << subsidy(h) << "\n";
    std::map<std::string,i64> bal{{std::string(128,'a'),987654321},{std::string(128,'b'),123456789}};
    std::map<std::string,i64> non{{std::string(128,'a'),7},{std::string(128,'b'),2}};
    std::string root=l2_state_root(bal,non);
    std::cout << "STATE_ROOT " << root << "\n";
    L2Deposit d; d.amount=COIN; d.l1_tx_id=sha3_512("deposit-tx"); d.l1_block_hash=sha3_512("deposit-block"); d.l2_recipient=std::string(128,'a'); d.claim_id=bridge_claim_id(d);
    std::cout << "CLAIM_ID " << d.claim_id << "\n";
    L2Withdrawal w; w.amount=COIN/2; w.l2_recipient=std::string(128,'b'); w.claim_id=withdrawal_claim_id(w);
    std::cout << "WITHDRAWAL_ID " << w.claim_id << "\n";
    std::cout << "RELEASE_ID " << withdrawal_release_id_fields(sha3_512("commit"),w.l2_recipient,w.claim_id,w.amount) << "\n";
    std::filesystem::path path=std::filesystem::temp_directory_path()/"em_v20_7_2_gate.json";
    std::error_code ec; std::filesystem::remove(path,ec);
    Blockchain bc(path.string());
    const Block& g=bc.chain.at(0);
    std::cout << "GEN_NONCE " << g.nonce << "\n";
    std::cout << "GEN_HASH " << g.block_hash << "\n";
    std::cout << "GEN_MERKLE " << g.merkle_root << "\n";
    Block parsed; if(!parse_block(g.json(),parsed) || parsed.block_hash!=g.block_hash) throw std::runtime_error("consensus gate block round-trip failed");
    std::cout << "ROUNDTRIP PASS\n";
    std::filesystem::remove(path,ec);
    std::cout << "CONSENSUS_GATE PASS\n";
}

void vector_test() {
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

void make_fixture(const std::string&path) {
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

void self_test() {
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
    json_object* dpo=json_tokener_parse(dp.json().c_str());
    bool dpok=dpo && parse_l2_deposit(dpo,dp);
    if(dpo) json_object_put(dpo);
    if(!dpok)throw std::runtime_error("deposit parser regression");
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


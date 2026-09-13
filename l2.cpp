#include "em/l2.hpp"

std::string L2Deposit::json() const { return canonical({{"amount",std::to_string(amount)},{"claim_id",json_escape(claim_id)},{"l1_block_hash",json_escape(l1_block_hash)},{"l1_tx_id",json_escape(l1_tx_id)},{"l2_recipient",json_escape(l2_recipient)}}); }

std::string L2Withdrawal::json() const { return canonical({{"amount",std::to_string(amount)},{"claim_id",json_escape(claim_id)},{"l2_recipient",json_escape(l2_recipient)},{"l2_tx_id",json_escape(l2_tx_id)}}); }

std::string L2Transaction::signing()const {
        return canonical({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"timestamp",std::to_string(timestamp)}});
    }

bool L2Transaction::valid()const {
        return amount>0&&is_hex(sender_pubkey,Wallet::PUB_HEX)&&is_hex(recipient,128)&&is_hex(signature,Wallet::SIG_HEX)&&
            tx_id==hash_obj({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"signature",json_escape(signature)},{"timestamp",std::to_string(timestamp)}})&&
            Wallet::verify(sender_pubkey,signing(),signature);
    }

std::string L2Transaction::json()const {
        return canonical({{"amount",std::to_string(amount)},{"nonce",std::to_string(nonce)},{"recipient",json_escape(recipient)},{"sender_pubkey",json_escape(sender_pubkey)},{"signature",json_escape(signature)},{"timestamp",std::to_string(timestamp)},{"tx_id",json_escape(tx_id)}});
    }

bool Layer2Sequencer::deposit(const std::string&a,i64 x) { if(!is_hex(a,128)||x<=0||x>MAX_SUPPLY)return false; if(balances[a]<0||balances[a]>MAX_SUPPLY-x)return false; balances[a]+=x; return true; }

bool Layer2Sequencer::claim_l1_deposit(const L2Deposit&d,const std::vector<Block>&l1_chain) {
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

bool Layer2Sequencer::request_withdrawal(const std::string&recipient,i64 x) {
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

bool Layer2Sequencer::add(const L2Transaction&t) {
        if(!t.valid()||t.amount<=0||t.amount>MAX_SUPPLY||t.nonce<0)return false;
        std::string sender=sha3_512(std::string((char*)unhex(t.sender_pubkey).data(),unhex(t.sender_pubkey).size()));
        if(mempool.empty()){batch_pre_balances=balances;batch_pre_nonces=nonces;batch_pre_poh=poh;batch_first_sequence=sequence+1;}
        if(t.nonce!=nonces[sender]||balances[sender]<t.amount)return false;
        if(nonces[sender]==std::numeric_limits<i64>::max())return false;
        if(balances[t.recipient]<0||balances[t.recipient]>MAX_SUPPLY-t.amount)return false;
        balances[sender]-=t.amount;balances[t.recipient]+=t.amount;nonces[sender]++;sequence++;poh=sha3_512(poh+t.tx_id);mempool.push_back(t);return mempool.size()<=MAX_L2_TX_PER_BATCH;
    }

std::optional<std::string>Layer2Sequencer::commit() {
        if(mempool.empty() && batch_withdrawals.empty() && batch_deposits.empty())return std::nullopt;
        std::vector<std::string>ids;for(auto&t:mempool)ids.push_back(t.tx_id);
        std::string root=merkle(ids),state_root=l2_state_root(balances,nonces);std::ostringstream prebo,preno;prebo<<"{";bool f=true;for(auto&[a,v]:batch_pre_balances){if(!f)prebo<<",";f=false;prebo<<json_escape(a)<<":"<<v;}prebo<<"}";preno<<"{";f=true;for(auto&[a,v]:batch_pre_nonces){if(!f)preno<<",";f=false;preno<<json_escape(a)<<":"<<v;}preno<<"}";
        std::ostringstream txs;txs<<"[";for(size_t i=0;i<mempool.size();++i){if(i)txs<<",";txs<<mempool[i].json();}txs<<"]";
        std::ostringstream deps; deps<<"["; for(size_t i=0;i<batch_deposits.size();++i){if(i)deps<<",";deps<<batch_deposits[i].json();} deps<<"]";
        std::ostringstream wds; wds<<"["; for(size_t i=0;i<batch_withdrawals.size();++i){if(i)wds<<",";wds<<batch_withdrawals[i].json();} wds<<"]";
        std::string c=canonical({{"count",std::to_string(mempool.size())}, {"deposits",deps.str()}, {"first_sequence",std::to_string(batch_first_sequence)}, {"last_sequence",std::to_string(sequence)}, {"poh",json_escape(poh)}, {"poh_prev",json_escape(batch_pre_poh)}, {"pre_balances",prebo.str()}, {"pre_nonces",preno.str()}, {"prev_state_root",json_escape(l2_state_root(batch_pre_balances,batch_pre_nonces))}, {"root",json_escape(root)}, {"state_root",json_escape(state_root)}, {"txs",txs.str()}, {"type",json_escape("l2_commitment")}, {"withdrawals",wds.str()}});
        std::string id=sha3_512(c),out=c.substr(0,c.size()-1)+",\"tx_id\":"+json_escape(id)+"}";commitments.push_back(out);mempool.clear();batch_pre_balances.clear();batch_pre_nonces.clear();batch_pre_poh.clear();batch_first_sequence=0;batch_deposits.clear();batch_withdrawals.clear();return out;
    }

std::string bridge_claim_id(const L2Deposit&d) { return sha3_512(canonical({{"amount",std::to_string(d.amount)},{"l1_block_hash",json_escape(d.l1_block_hash)},{"l1_tx_id",json_escape(d.l1_tx_id)},{"l2_recipient",json_escape(d.l2_recipient)}})); }

std::string withdrawal_claim_id(const L2Withdrawal&w) { return sha3_512(canonical({{"amount",std::to_string(w.amount)},{"l2_recipient",json_escape(w.l2_recipient)},{"l2_tx_id",json_escape(w.l2_tx_id)}})); }

bool parse_l2_deposit(json_object*o,L2Deposit&d) { return o&&json_object_is_type(o,json_type_object)&&json_get_string(o,"l1_tx_id",d.l1_tx_id)&&json_get_string(o,"l1_block_hash",d.l1_block_hash)&&json_get_string(o,"l2_recipient",d.l2_recipient)&&json_get_string(o,"claim_id",d.claim_id)&&json_get_i64(o,"amount",d.amount)&&d.amount>0&&d.amount<=MAX_SUPPLY&&is_hex(d.l1_tx_id,128)&&is_hex(d.l1_block_hash,128)&&is_hex(d.l2_recipient,128)&&is_hex(d.claim_id,128)&&d.claim_id==bridge_claim_id(d); }

bool parse_l2_withdrawal(json_object*o,L2Withdrawal&w) { return o&&json_object_is_type(o,json_type_object)&&json_get_string(o,"l2_tx_id",w.l2_tx_id)&&json_get_string(o,"l2_recipient",w.l2_recipient)&&json_get_string(o,"claim_id",w.claim_id)&&json_get_i64(o,"amount",w.amount)&&w.amount>0&&w.amount<=MAX_SUPPLY&&is_hex(w.l2_tx_id,128)&&is_hex(w.l2_recipient,128)&&is_hex(w.claim_id,128)&&w.claim_id==withdrawal_claim_id(w); }

std::string l2_state_root(const std::map<std::string,i64>&balances,const std::map<std::string,i64>&nonces) {
    std::ostringstream bo,no; bo<<"{"; bool f=true; for(auto&[a,v]:balances){if(!f)bo<<",";f=false;bo<<json_escape(a)<<":"<<v;} bo<<"}";
    no<<"{"; f=true; for(auto&[a,v]:nonces){if(!f)no<<",";f=false;no<<json_escape(a)<<":"<<v;} no<<"}";
    return hash_obj({{"balances",bo.str()},{"nonces",no.str()}});
}

bool parse_l2_map(json_object*o,const char*key,std::map<std::string,i64>&out) {
    json_object*v=nullptr; if(!json_object_object_get_ex(o,key,&v)||!v||!json_object_is_type(v,json_type_object))return false;
    json_object_object_foreach(v,k,val){ if(!json_object_is_type(val,json_type_int))return false; i64 x=json_object_get_int64(val); if(x<0||x>MAX_SUPPLY)return false; if(!is_hex(k,128))return false; out[k]=x; }
    return true;
}

bool parse_l2_tx(json_object*v,L2Transaction&t) {
    return v&&json_object_is_type(v,json_type_object)&&json_get_string(v,"sender_pubkey",t.sender_pubkey)&&json_get_string(v,"recipient",t.recipient)&&json_get_string(v,"signature",t.signature)&&json_get_string(v,"tx_id",t.tx_id)&&json_get_i64(v,"amount",t.amount)&&json_get_i64(v,"nonce",t.nonce)&&json_get_i64(v,"timestamp",t.timestamp);
}

std::string last_l2_state_root(const std::vector<Block>&prefix) {
    const std::map<std::string,i64> empty_b, empty_n;
    const std::string genesis=l2_state_root(empty_b,empty_n);
    for(auto bi=prefix.rbegin();bi!=prefix.rend();++bi) {
        for(auto ti=bi->transactions.rbegin();ti!=bi->transactions.rend();++ti) {
            json_object*o=json_tokener_parse(ti->c_str()); if(!o)continue; std::string typ,sr; bool ok=json_get_string(o,"type",typ)&&typ=="l2_commitment"&&json_get_string(o,"state_root",sr)&&is_hex(sr,128); json_object_put(o); if(ok)return sr;
        }
    }
    return genesis;
}

bool commitment_has_withdrawal(json_object*commit,const std::string&claim_id,const std::string&recipient,i64 amount) {
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

bool prior_release_exists(const std::vector<Block>&prefix,const std::string&claim_id) {
    for(const auto&b:prefix) for(const auto&raw:b.transactions) {
        json_object*o=json_tokener_parse(raw.c_str()); if(!o) continue;
        std::string type,claim;
        bool ok=json_get_string(o,"type",type)&&type=="l2_withdrawal_release"&&json_get_string(o,"claim_id",claim)&&claim==claim_id;
        json_object_put(o); if(ok) return true;
    }
    return false;
}

bool find_finalized_withdrawal(const std::vector<Block>&prefix,const std::string&commitment_hash,const std::string&claim_id,const std::string&recipient,i64 amount) {
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

bool find_finalized_deposit(const std::vector<Block>&prefix,const L2Deposit&d) {
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

bool verify_l2_deposit_manifest(json_object*o,const std::vector<Block>&prefix) {
    json_object*da=nullptr;
    if(!json_object_object_get_ex(o,"deposits",&da)||!da||!json_object_is_type(da,json_type_array)||json_object_array_length(da)>MAX_L2_DEPOSITS_PER_BATCH)return false;
    std::set<std::string>seen;
    for(size_t i=0;i<(size_t)json_object_array_length(da);++i) {
        L2Deposit d;
        if(!parse_l2_deposit(json_object_array_get_idx(da,i),d)||!seen.insert(d.claim_id).second||prior_release_exists(prefix,d.claim_id)||!find_finalized_deposit(prefix,d))return false;
    }
    return true;
}

bool verify_l2_commitment(json_object*o,const std::string&expected_prev_root) {
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


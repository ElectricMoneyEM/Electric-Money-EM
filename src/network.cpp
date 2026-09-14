#include "em/network.hpp"

SeenSet::SeenSet(size_t c):cap(c) {
    }

bool SeenSet::contains(const std::string&x) {
        return s.count(x);
    }

void SeenSet::add(const std::string&x) {
        if(s.count(x))return;
        s.insert(x);
        q.push_back(x);
        if(q.size()>cap) {
            s.erase(q.front());
            q.pop_front();
        }
    }

bool P2PNode::valid_hello(json_object*o) {
        std::string net; int pv=0,ppv=0;
        return json_get_string(o,"network_id",net)&&json_get_int(o,"protocol_version",pv)&&json_get_int(o,"p2p_version",ppv)&&net==NETWORK_ID&&pv==PROTOCOL_VERSION&&ppv==P2P_PROTOCOL_VERSION;
    }

std::string P2PNode::msg(const std::string&type,const std::string&payload) { return payload.empty()?"{\"type\":"+json_escape(type)+"}":"{\"type\":"+json_escape(type)+",\"payload\":"+json_escape(payload)+"}"; }

std::string P2PNode::msg_num(const std::string&type,const std::string&payload) { return "{\"type\":"+json_escape(type)+",\"payload\":"+payload+"}"; }

void P2PNode::remember_peer(const std::string&host,int port) {
        if(port<1||port>65535||host.empty())return;
        std::lock_guard<std::mutex>g(peers_mu);
        std::string k=host+":"+std::to_string(port);
        if(peers.size()<MAX_PEERS||peers.count(k)) peers[k]={host,port};
    }

bool P2PNode::send_blocks(em_socket_t fd,size_t start) {
        auto c=bc.snapshot_from(start,MAX_BLOCKS_RESPONSE);
        std::string cj=chain_json(c);
        if(cj.empty()) return send_frame(fd,msg("error","blocks_too_large"));
        return send_frame(fd,msg("blocks",cj));
    }

void P2PNode::handle(em_socket_t fd,std::string remote_host,int remote_port) {
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

em_socket_t P2PNode::connect_peer() {
        addrinfo hints{},*res=nullptr; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
        std::string ps=std::to_string(peer_port); if(getaddrinfo(peer_host.c_str(),ps.c_str(),&hints,&res)!=0)return EM_INVALID_SOCKET;
        em_socket_t fd=EM_INVALID_SOCKET; for(addrinfo*r=res;r;r=r->ai_next){fd=socket(r->ai_family,r->ai_socktype,r->ai_protocol); if(fd==EM_INVALID_SOCKET)continue; if(connect(fd,r->ai_addr,r->ai_addrlen)==0)break; em_socket_close(fd);fd=EM_INVALID_SOCKET;} freeaddrinfo(res); return fd;
    }

bool P2PNode::handshake(em_socket_t fd) {
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

bool P2PNode::request_range(em_socket_t fd,size_t start,std::vector<Block>&out) {
        std::string req="{\"type\":\"getblocks\",\"start\":"+std::to_string(start)+"}"; if(!send_frame(fd,req))return false; auto r=recv_frame(fd);if(!r)return false;json_object*o=json_tokener_parse(r->c_str());if(!o)return false;std::string type,payload;json_get_string(o,"type",type);json_get_string(o,"payload",payload);json_object_put(o);if(type!="blocks")return false;std::vector<Block>v;if(!parse_chain(payload,v))return false;out.insert(out.end(),v.begin(),v.end());return true;
    }

void P2PNode::sync_once() {
        em_socket_t fd=connect_peer(); if(fd==EM_INVALID_SOCKET)return; timeval tv{P2P_HANDSHAKE_TIMEOUT_SEC,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
        if(!handshake(fd)){em_socket_close(fd);return;} auto local=bc.snapshot_chain(); size_t start=local.size(); std::vector<Block>remote;
        while(true){std::vector<Block>chunk;if(!request_range(fd,start,chunk))break;if(chunk.empty())break;remote.insert(remote.end(),chunk.begin(),chunk.end());start+=chunk.size();if(chunk.size()<MAX_BLOCKS_RESPONSE)break;}
        if(!remote.empty()) { std::vector<Block>candidate=local; if(remote.front().index==static_cast<int>(candidate.size()))candidate.insert(candidate.end(),remote.begin(),remote.end()); else { candidate.clear(); std::vector<Block>tmp; size_t pos=0; while(true){std::vector<Block>ch;if(!request_range(fd,pos,ch))break;if(ch.empty())break;tmp.insert(tmp.end(),ch.begin(),ch.end());pos+=ch.size();if(ch.size()<MAX_BLOCKS_RESPONSE)break;} if(!tmp.empty())candidate=std::move(tmp); } bc.replace_chain(candidate); }
        send_frame(fd,msg("bye"));em_socket_close(fd);
    }

P2PNode::P2PNode(Blockchain&b,int lp):bc(b),listen_port(lp) { em_socket_init(); }

P2PNode::P2PNode(Blockchain&b,const std::string&h,int p):bc(b),peer_host(h),peer_port(p) { em_socket_init(); }

void P2PNode::serve() {
        em_socket_init(); server_fd=socket(AF_INET,SOCK_STREAM,0); if(server_fd==EM_INVALID_SOCKET)throw std::runtime_error("P2P socket failed"); int one=1; setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons((uint16_t)listen_port); if(bind(server_fd,(sockaddr*)&a,sizeof(a))<0||listen(server_fd,MAX_PEERS)<0){em_socket_close(server_fd);server_fd=EM_INVALID_SOCKET;throw std::runtime_error("P2P bind/listen failed");}
        std::cout<<"[P2P] listening on 0.0.0.0:"<<listen_port<<"\n";
        while(!stop){sockaddr_storage ss{};
#ifdef _WIN32
        int n=sizeof(ss);
#else
        socklen_t n=sizeof(ss);
#endif
        em_socket_t fd=accept(server_fd,(sockaddr*)&ss,&n);
        if(fd==EM_INVALID_SOCKET)break;std::string rh="peer";int rp=0;if(ss.ss_family==AF_INET){auto*a=(sockaddr_in*)&ss;char buf[INET_ADDRSTRLEN];if(inet_ntop(AF_INET,&a->sin_addr,buf,sizeof(buf)))rh=buf;rp=ntohs(a->sin_port);}std::thread([this,fd,rh,rp]{handle(fd,rh,rp);em_socket_close(fd);}).detach();}
    }

void P2PNode::sync_loop() {while(!stop){sync_once();for(int i=0;i<15&&!stop;++i)std::this_thread::sleep_for(std::chrono::seconds(1));}}

bool send_all(em_socket_t fd,const char*p,size_t n) {
    while(n) {
        const int chunk=static_cast<int>(std::min<size_t>(n,static_cast<size_t>(INT_MAX)));
        const int r=send(fd,p,chunk,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}

bool recv_all(em_socket_t fd,char*p,size_t n) {
    while(n) {
        const int chunk=static_cast<int>(std::min<size_t>(n,static_cast<size_t>(INT_MAX)));
        const int r=recv(fd,p,chunk,0);
        if(r<=0)return false;
        p+=r;
        n-=r;
    }
    return true;
}

bool send_frame(em_socket_t fd,const std::string&s) {
    if(s.size()>MAX_FRAME_BYTES)return false;
    uint32_t n=htonl((uint32_t)s.size());
    return send_all(fd,(char*)&n,4)&&send_all(fd,s.data(),s.size());
}

std::optional<std::string> recv_frame(em_socket_t fd) {
    uint32_t n=0;
    if(!recv_all(fd,(char*)&n,4))return std::nullopt;
    n=ntohl(n);
    if(n==0||n>MAX_FRAME_BYTES)return std::nullopt;
    std::string s(n,'\0');
    if(!recv_all(fd,s.data(),n))return std::nullopt;
    return s;
}


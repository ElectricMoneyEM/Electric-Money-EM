#pragma once

#include "common.hpp"
#include "block.hpp"
#include "blockchain.hpp"

class SeenSet {
    size_t cap;
    std::set<std::string>s;
    std::deque<std::string>q;
    explicit SeenSet(size_t c);
bool contains(const std::string&x);
void add(const std::string&x);

};
bool send_all(int fd,const char*p,size_t n);

bool recv_all(int fd,char*p,size_t n);

bool send_frame(int fd,const std::string&s);

std::optional<std::string> recv_frame(int fd);


class P2PNode {
    Blockchain&bc; int listen_port=0; std::string peer_host; int peer_port=0; std::atomic<bool>stop{false}; int server_fd=-1;
    std::mutex peers_mu;
    std::map<std::string,std::pair<std::string,int>> peers;
    static constexpr size_t MAX_BLOCKS_RESPONSE=128;static bool valid_hello(json_object*o);
static std::string msg(const std::string&type,const std::string&payload="");
static std::string msg_num(const std::string&type,const std::string&payload);
void remember_peer(const std::string&host,int port);
bool send_blocks(int fd,size_t start);
void handle(int fd,std::string remote_host,int remote_port);
int connect_peer();
bool handshake(int fd);
bool request_range(int fd,size_t start,std::vector<Block>&out);
void sync_once();
P2PNode(Blockchain&b,int lp);
P2PNode(Blockchain&b,const std::string&h,int p);
void serve();
void sync_loop();

};



#include "em/common.hpp"

#ifdef _WIN32
void em_socket_init() {
    static std::once_flag once;
    static int result = 0;
    std::call_once(once, [] {
        WSADATA wsa{};
        result = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    if(result != 0) throw std::runtime_error("WSAStartup failed");
}

void em_socket_close(em_socket_t fd) {
    if(fd != EM_INVALID_SOCKET) closesocket(fd);
}

bool em_sync_file(const std::string&path) {
    HANDLE h=CreateFileA(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE) return false;
    const BOOL ok=FlushFileBuffers(h);
    CloseHandle(h);
    return ok != 0;
}

bool em_atomic_replace(const std::string&from,const std::string&to) {
    return MoveFileExA(from.c_str(),to.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
}
#else
void em_socket_init() {}

void em_socket_close(em_socket_t fd) {
    if(fd != EM_INVALID_SOCKET) ::close(fd);
}

bool em_sync_file(const std::string&path) {
    int fd=::open(path.c_str(),O_RDONLY);
    if(fd<0) return false;
    const bool ok=::fsync(fd)==0;
    ::close(fd);
    return ok;
}

bool em_atomic_replace(const std::string&from,const std::string&to) {
    return std::rename(from.c_str(),to.c_str())==0;
}
#endif

i64 now_s() {
    return (i64)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string hex(const unsigned char*p,size_t n) {
    static const char*h="0123456789abcdef";
    std::string s;
    s.resize(n*2);
    for(size_t i=0;i<n;i++) {
        s[2*i]=h[p[i]>>4];
        s[2*i+1]=h[p[i]&15];
    }
    return s;
}

std::vector<unsigned char> unhex(const std::string&s) {
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

std::string json_escape(const std::string&s) {
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

std::string sha3_512(const std::string&s) {
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

std::string canonical(const std::map<std::string,std::string>&raw) {
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

std::string hash_obj(const std::map<std::string,std::string>&m) {
    return sha3_512(canonical(m));
}

bool is_hex(const std::string&s,size_t len) {
    if(s.size()!=len)return false;
    for(char c:s)if(!std::isxdigit((unsigned char)c))return false;
    return true;
}

bool json_get_string(json_object*o,const char*k,std::string&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_string)) return false;
    out=json_object_get_string(v);
    return true;
}

bool json_get_i64(json_object*o,const char*k,i64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    out=json_object_get_int64(v);
    return true;
}

bool json_get_u64(json_object*o,const char*k,u64&out) {
    json_object*v=nullptr;
    if(!o || !json_object_is_type(o,json_type_object) || !json_object_object_get_ex(o,k,&v) || !v || !json_object_is_type(v,json_type_int)) return false;
    int64_t x=json_object_get_int64(v);
    if(x<0) return false;
    out=static_cast<u64>(x);
    return true;
}

bool json_get_int(json_object*o,const char*k,int&out) {
    i64 x=0;
    if(!json_get_i64(o,k,x) || x<INT_MIN || x>INT_MAX) return false;
    out=static_cast<int>(x);
    return true;
}

i64 checked_amount(i64 x) {
    if(x<=0||x>MAX_TX_AMOUNT)throw std::runtime_error("amount outside allowed range");
    return x;
}


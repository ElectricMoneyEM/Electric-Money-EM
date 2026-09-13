#include "em/wallet.hpp"

Wallet::Wallet() {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
        if(!c)throw std::runtime_error("OpenSSL 3.5+ ML-DSA-65 unavailable");
        if(EVP_PKEY_keygen_init(c)<=0||EVP_PKEY_keygen(c,&pkey)<=0) {
            EVP_PKEY_CTX_free(c);
            throw std::runtime_error("ML-DSA keygen failed");
        }
        EVP_PKEY_CTX_free(c);
        size_t n=0;
        if(EVP_PKEY_get_raw_public_key(pkey,nullptr,&n)<=0||n!=MLDSA65_PUBLIC_KEY_BYTES)throw std::runtime_error("bad ML-DSA public key size");
        std::vector<unsigned char>pub(n);
        if(EVP_PKEY_get_raw_public_key(pkey,pub.data(),&n)<=0)throw std::runtime_error("public key export failed");
        public_key_hex=hex(pub.data(),pub.size());
        address=sha3_512(std::string((char*)pub.data(),pub.size()));
    }

Wallet::~Wallet() {
        EVP_PKEY_free(pkey);
    }

std::string Wallet::sign(const std::string&msg)const {
        EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_pkey(nullptr,pkey,nullptr);
        EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
        if(!c||!alg)throw std::runtime_error("ML-DSA sign setup");
        if(EVP_PKEY_sign_message_init(c,alg,nullptr)<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign init");
        }
        size_t n=0;
        if(EVP_PKEY_sign(c,nullptr,&n,(const unsigned char*)msg.data(),msg.size())<=0||n!=MLDSA65_SIGNATURE_BYTES) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA signature size");
        }
        std::vector<unsigned char>s(n);
        if(EVP_PKEY_sign(c,s.data(),&n,(const unsigned char*)msg.data(),msg.size())<=0) {
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            throw std::runtime_error("ML-DSA sign");
        }
        EVP_PKEY_CTX_free(c);
        EVP_SIGNATURE_free(alg);
        return hex(s.data(),n);
    }

bool Wallet::verify(const std::string&pubhex,const std::string&msg,const std::string&sighex) {
        try {
            if(!is_hex(pubhex,PUB_HEX)||!is_hex(sighex,SIG_HEX))return false;
            auto pub=unhex(pubhex),sig=unhex(sighex);
            EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_from_name(nullptr,PQ_ALG.c_str(),nullptr);
            if(!c)return false;
            if(EVP_PKEY_fromdata_init(c)<=0)return false;
            OSSL_PARAM params[2];
            params[0]=OSSL_PARAM_construct_octet_string("pub",pub.data(),pub.size());
            params[1]=OSSL_PARAM_construct_end();
            EVP_PKEY*pk=nullptr;
            if(EVP_PKEY_fromdata(c,&pk,EVP_PKEY_PUBLIC_KEY,params)<=0) {
                EVP_PKEY_CTX_free(c);
                return false;
            }
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE*alg=EVP_SIGNATURE_fetch(nullptr,"ML-DSA-65",nullptr);
            c=EVP_PKEY_CTX_new_from_pkey(nullptr,pk,nullptr);
            bool ok=false;
            if(c&&alg&&EVP_PKEY_verify_message_init(c,alg,nullptr)>0)ok=EVP_PKEY_verify(c,sig.data(),sig.size(),(const unsigned char*)msg.data(),msg.size())==1;
            EVP_PKEY_CTX_free(c);
            EVP_SIGNATURE_free(alg);
            EVP_PKEY_free(pk);
            return ok;
        } catch(...) {
            return false;
        }
    }


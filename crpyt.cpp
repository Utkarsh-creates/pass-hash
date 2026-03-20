#include<iostream>
#include<string>
#include<exception>
#include<vector>
#include <iomanip>
extern "C" {
 #include "external/include/argon2.h"
}
class Encryptor{
public:
virtual void encrypt(const std::string& data)=0;
virtual ~Encryptor() {}
};

class AESEncryptor : public Encryptor{
public:
void encrypt(const std::string& data) override{
    uint32_t t_cost=2;
    uint32_t m_cost=1<<16;
    uint32_t parallelism=1;

    uint32_t hash_len=32;
    std::vector<uint8_t> hash(hash_len);

    std::string dummy_salt="1234567812345678";

    int result = argon2id_hash_raw(
        t_cost, m_cost, parallelism, data.data(), data.size(),
        dummy_salt.data(),dummy_salt.size(),hash.data(),hash.size()
    );
if (result !=ARGON2_OK){
    throw std::runtime_error("Encryption failed with error code: " + std::to_string(result));
}
std::cout<<"Successfully hashed password to a 32-byte key!"<<std::endl;
std::cout << "Your 256-bit Key (Hex): ";
for (uint8_t byte : hash) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
}
std::cout << std::dec << std::endl;
}
};
class Credentials{
    private:        
    std::string password;
    std::string salt;
    public:
    Credentials(const std::string p):password(p){
        if (password.length()<8){
            throw std::runtime_error("Password must be at least 8 characters long");
        }
    }
};

int main()
{
    try{
        std::string pass="1234567890";
        Credentials myUser(pass);
        AESEncryptor myEngine;
        myEngine.encrypt(pass);
    }
    catch(const std::runtime_error& e){
        std::cerr<< "Security Error: "<< e.what() << std::endl;
    }
    return 0;
}
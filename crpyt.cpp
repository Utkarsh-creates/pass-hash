#include<iostream>
#include<string>
#include<exception>
#include<vector>
#include <iomanip>
#include<random>
extern "C" {
 #include "external/include/argon2.h"
}
class Credentials{
    private:        
    std::string username;
    std::string password;
    std::vector<uint8_t> salt;
    public:
    Credentials(const std::string p):password(p){
        if (password.length()<8){
            throw std::runtime_error("Password must be at least 8 characters long");
        }
        generateSalt(16);
    }

    void generateSalt(size_t length){
        salt.resize(length);
        std::random_device rd;
        for (auto& byte : salt){
            byte=static_cast<uint8_t>(rd());
        }
    }
    const std::string& getPassword() const { return password; }
    const std::vector<uint8_t>& getSalt() const { return salt; }
};
class Encryptor{
public:
virtual void encrypt(const class Credentials& creds)=0;
virtual ~Encryptor() {}
};

class AESEncryptor : public Encryptor{
private:
const std::string secret_pepper = "S3cr3t_P3pp3r_SRMIST_2026!#$";
public:
void encrypt(const class Credentials& creds) override{
    uint32_t t_cost=2;
    uint32_t m_cost=1<<16;
    uint32_t parallelism=1;

    uint32_t hash_len=32;
    std::vector<uint8_t> hash(hash_len);
    std::string pass = creds.getPassword()+secret_pepper;
    const std::vector<uint8_t>& salt = creds.getSalt();
    int result = argon2id_hash_raw(
        t_cost, m_cost, parallelism, pass.data(), pass.size(),salt.data(), salt.size(),hash.data(),hash.size()
    );
    for (char &c : pass) {
    c = '\0';
}
if (result !=ARGON2_OK){
    throw std::runtime_error("Encryption failed with error code: " + std::to_string(result));
}
std::cout<<"Successfully hashed with Random Salt!"<<std::endl;
std::cout << "Salt (Hex): ";
        for (uint8_t b : salt) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
std::cout << "Your 256-bit Key (Hex): ";
for (uint8_t byte : hash) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
}
std::cout << std::dec << std::endl;
}

};



int main()
{
    try{
        std::string pass;
        std::cout << "Password: ";
        std::getline(std::cin, pass);
        Credentials myUser(pass);
        AESEncryptor myEngine;
        myEngine.encrypt(myUser);
    }
    catch(const std::runtime_error& e){
        std::cerr<< "Security Error: "<< e.what() << std::endl;
    }
    return 0;
}
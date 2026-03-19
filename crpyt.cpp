#include<iostream>
#include<string>
#include<exception>
#include<vector>
class Encryptor{
public:
virtual void encrypt(const std::string& data)=0;
virtual ~Encryptor() {}
};

class AESEncryptor : public Encryptor{
public:
void encrypt(const std::string& data) override{
    std::cout<<"Encrypting data using AES: "<<data<<std::endl;
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
        Credentials myUser("123567832");
    }
    catch(const std::runtime_error& e){
        std::cerr<< "Security Error: "<< e.what() << std::endl;
    }
    return 0;
}
// include standard headers...

#include<des.cpp>

int main() {
  
  std::string message = "hello"; // message
  std::string key = "12345678"; // key, must be at least 64bit long, if size exceeds 64bits(8 bytes) it will be truncated

  DES::DES_Encryption<bool> DES(key); // DES init
  
  /** ENCRYPTION **/
  std::vector<bool> encrypted = DES.Encrypt(DES::DES_Encryption<bool>::toBinary(DES::DES_Encryption<bool>::toByteArray<char>(message)));
  std::cout << "Encrypted: " << DES::DES_Encryption<bool>::toByteString<char>(DES::DES_Encryption<bool>::toHex<bool>(encrypted))<< "\n";

  /** DECRYPTION **/
  std::vector<bool> decrypted = DES.Decrypt(encrypted);
  std::cout << "Decrypted: "<< DES::DES_Encryption<bool>::toByteString<char>(DES::DES_Encryption<bool>::toAscii<bool, char>(decrypted))<< "\n";
        
}

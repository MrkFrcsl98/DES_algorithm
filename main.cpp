#include "des.hpp"
#include <iostream>

int main() {
#ifdef _DES_ENCRYPTION_ALGORITHM_
  {
    using namespace DES;
    /** PREPARE DATA **/
    std::string message = "this is a secret message...";
    std::string key = "12345678";

    DES::DES_Encryption DES(key); // DES object initialization with key as argument

    /** ENCRYPTION **/
    const DES_Encryption::tBitStream encrypted_as_binary = DES.Encrypt(message); // encrypt message, returns a vector<bool> containing binary data
    std::cout << "Encrypted: " << DES_Encryption::toByteString(DES_Encryption::binToHex(encrypted_as_binary)) << "\n"; // parse for output

    /** DECRYPTION **/
    DES_Encryption::tBitStream decrypted_as_binary = DES.Decrypt(encrypted_as_binary); // decrypt ciphertext
    std::cout << "Decrypted: " << DES_Encryption::toByteString(DES_Encryption::toAscii(decrypted_as_binary)) << "\n";  // parse for output
  }
#endif
}

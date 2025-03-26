#include "des.hpp"

int main() {
#ifdef _DES_ENCRYPTION_ALGORITHM_
  {
    using namespace DES;
    /** PREPARE DATA **/
    std::string message = "hello";
    std::string key = "12345678";

    std::vector<std::uint8_t> byte_array = DES_Encryption::toByteArray(message);
    DES_Encryption::tBitStream binary_message = DES_Encryption::toBinary(byte_array);

    DES::DES_Encryption DES(key);

    /** ENCRYPTION **/
    DES_Encryption::tBitStream encrypted = DES.Encrypt(binary_message);
    std::vector<std::uint8_t> toHex = DES_Encryption::binToHex(encrypted);
    std::string toString = DES_Encryption::toByteString(toHex);
    std::cout << "Encrypted: " << toString << "\n";

    /** DECRYPTION **/
    DES_Encryption::tBitStream decrypted = DES.Decrypt(encrypted);
    std::vector<unsigned char> decryptedAscii = DES_Encryption::toAscii(decrypted);
    std::string dAsciiString = DES_Encryption::toByteString(decryptedAscii);
    std::cout << "Decrypted: " << dAsciiString << "\n";
  }
#endif
}

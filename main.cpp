#include "des.hpp" // include the DES file
#include <iostream> // include this header for std::cout operations

int main(int argc, char** argc) {
#ifdef _DES_ENCRYPTION_ALGORITHM_
  {
    using namespace DES;
    /** PREPARE DATA **/
    std::string message = "some random message to be encrypted..."; // message
    std::string key = "12345678"; // encryption key, must be 8 bytes long!

    std::vector<std::uint8_t> byte_array = DES_Encryption::toByteArray(message); // convert string message to vector type
    DES_Encryption::tBitStream binary_message = DES_Encryption::toBinary(byte_array); // now convert to binary, tBitStream is a type representing std::vector<bool> object

    DES::DES_Encryption DES(key); // DES object initialization with key as argument

    /** ENCRYPTION **/
    DES_Encryption::tBitStream encrypted = DES.Encrypt(binary_message); // encrypt message, returns a vector<bool> containing binary data
    std::vector<std::uint8_t> toHex = DES_Encryption::binToHex(encrypted); // convert to hex(optional)
    std::string toString = DES_Encryption::toByteString(toHex); // convert to string(optional)
    std::cout << "Encrypted: " << toString << "\n";

    /** DECRYPTION **/
    DES_Encryption::tBitStream decrypted = DES.Decrypt(encrypted); // decrypt ciphertext
    std::vector<unsigned char> decryptedAscii = DES_Encryption::toAscii(decrypted); // convert to ascii(optional)
    std::string dAsciiString = DES_Encryption::toByteString(decryptedAscii); // convert to string(optional)
    std::cout << "Decrypted: " << dAsciiString << "\n"; 
  }
#endif
}

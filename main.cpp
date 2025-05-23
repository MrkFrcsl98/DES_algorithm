#include <iostream>
#include <vector>
#include "des.hpp"

int main() {
    std::string key = "mySecrK1";  // 8 bytes for DES
    std::string text = "Hello, DES encryption and decryption demo!";
    std::string key2 = "mySecrK2";
    std::string key3 = "mySecrK3";

    // --- ECB Mode ---
    auto ecb_enc = DES::ECB::Encrypt(text, key);
    std::cout << "ECB Encrypted (hex): " << ecb_enc.toHex() << std::endl;
    std::cout << "ECB Encrypted (base64): " << ecb_enc.toBase64() << std::endl;

    auto ecb_dec = DES::ECB::Decrypt(ecb_enc.toString(), key);
    std::cout << "ECB Decrypted: " << ecb_dec.toString() << std::endl;

    // --- CBC Mode ---
    std::vector<bool> iv(64, 1); // example IV (all bits set)
    auto cbc_enc = DES::CBC::Encrypt(text, key, iv);
    std::cout << "CBC Encrypted (hex): " << cbc_enc.toHex() << std::endl;

    auto cbc_dec = DES::CBC::Decrypt(cbc_enc.toString(), key, iv);
    std::cout << "CBC Decrypted: " << cbc_dec.toString() << std::endl;

    // --- CFB Mode ---
    auto cfb_enc = DES::CFB::Encrypt(text, key, iv);
    std::cout << "CFB Encrypted (hex): " << cfb_enc.toHex() << std::endl;

    auto cfb_dec = DES::CFB::Decrypt(cfb_enc.toString(), key, iv);
    std::cout << "CFB Decrypted: " << cfb_dec.toString() << std::endl;

    // --- OFB Mode ---
    auto ofb_enc = DES::OFB::Encrypt(text, key, iv);
    std::cout << "OFB Encrypted (hex): " << ofb_enc.toHex() << std::endl;

    auto ofb_dec = DES::OFB::Decrypt(ofb_enc.toString(), key, iv);
    std::cout << "OFB Decrypted: " << ofb_dec.toString() << std::endl;

    // --- CTR Mode ---
    uint64_t nonce = 12345;
    auto ctr_enc = DES::CTR::Encrypt(text, key, nonce);
    std::cout << "CTR Encrypted (hex): " << ctr_enc.toHex() << std::endl;

    auto ctr_dec = DES::CTR::Decrypt(ctr_enc.toString(), key, nonce);
    std::cout << "CTR Decrypted: " << ctr_dec.toString() << std::endl;

    // --- Triple DES, ECB Mode ---
    auto tdes_enc = DES::ECB::Encrypt3DES(text, key, key2, key3);
    std::cout << "3DES ECB Encrypted (hex): " << tdes_enc.toHex() << std::endl;

    auto tdes_dec = DES::ECB::Decrypt3DES(tdes_enc.toString(), key, key2, key3);
    std::cout << "3DES ECB Decrypted: " << tdes_dec.toString() << std::endl;

    // --- Triple DES, CBC Mode ---
    auto tdes_cbc_enc = DES::CBC::Encrypt3DES(text, key, key2, key3, iv);
    std::cout << "3DES CBC Encrypted (hex): " << tdes_cbc_enc.toHex() << std::endl;

    auto tdes_cbc_dec = DES::CBC::Decrypt3DES(tdes_cbc_enc.toString(), key, key2, key3, iv);
    std::cout << "3DES CBC Decrypted: " << tdes_cbc_dec.toString() << std::endl;

    return 0;
}

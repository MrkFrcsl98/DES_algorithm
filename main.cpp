#include "des.hpp"
#include <iostream>
#include <iomanip>

int main() {
    std::string key = "12345678";
    std::string k1 = "12345678", k2 = "abcdefgh", k3 = "ABCDEFGH";
    std::string plaintext = "Attack at dawn! This is a test message.";
    std::vector<bool> iv(64, 0); // All-zero IV for demonstration
    uint64_t nonce = 42;

    std::cout << "Original: " << plaintext << std::endl;

    // --- DES, ECB ---
    auto ecb_enc = DES::ECB::Encrypt(plaintext, key);
    auto ecb_dec = DES::ECB::Decrypt(ecb_enc.toString(), key);
    std::cout << "\nDES ECB Enc Hex: " << ecb_enc.toHex();
    std::cout << "\nDES ECB Dec: " << ecb_dec.toString();

    // --- DES, CBC ---
    auto cbc_enc = DES::CBC::Encrypt(plaintext, key, iv);
    auto cbc_dec = DES::CBC::Decrypt(cbc_enc.toString(), key, iv);
    std::cout << "\n\nDES CBC Enc Hex: " << cbc_enc.toHex();
    std::cout << "\nDES CBC Dec: " << cbc_dec.toString();

    // --- DES, CFB ---
    auto cfb_enc = DES::CFB::Encrypt(plaintext, key, iv);
    auto cfb_dec = DES::CFB::Decrypt(cfb_enc.toString(), key, iv);
    std::cout << "\n\nDES CFB Enc Hex: " << cfb_enc.toHex();
    std::cout << "\nDES CFB Dec: " << cfb_dec.toString();

    // --- DES, OFB ---
    auto ofb_enc = DES::OFB::Encrypt(plaintext, key, iv);
    auto ofb_dec = DES::OFB::Decrypt(ofb_enc.toString(), key, iv);
    std::cout << "\n\nDES OFB Enc Hex: " << ofb_enc.toHex();
    std::cout << "\nDES OFB Dec: " << ofb_dec.toString();

    // --- DES, CTR ---
    auto ctr_enc = DES::CTR::Encrypt(plaintext, key, nonce);
    auto ctr_dec = DES::CTR::Decrypt(ctr_enc.toString(), key, nonce);
    std::cout << "\n\nDES CTR Enc Hex: " << ctr_enc.toHex();
    std::cout << "\nDES CTR Dec: " << ctr_dec.toString();

    // --- 3DES, ECB ---
    auto tdes_ecb_enc = DES::ECB::Encrypt3DES(plaintext, k1, k2, k3);
    auto tdes_ecb_dec = DES::ECB::Decrypt3DES(tdes_ecb_enc.toString(), k1, k2, k3);
    std::cout << "\n\n3DES ECB Enc Hex: " << tdes_ecb_enc.toHex();
    std::cout << "\n3DES ECB Dec: " << tdes_ecb_dec.toString();

    // --- 3DES, CBC ---
    auto tdes_cbc_enc = DES::CBC::Encrypt3DES(plaintext, k1, k2, k3, iv);
    auto tdes_cbc_dec = DES::CBC::Decrypt3DES(tdes_cbc_enc.toString(), k1, k2, k3, iv);
    std::cout << "\n\n3DES CBC Enc Hex: " << tdes_cbc_enc.toHex();
    std::cout << "\n3DES CBC Dec: " << tdes_cbc_dec.toString();

    std::cout << std::endl;
    return 0;
}

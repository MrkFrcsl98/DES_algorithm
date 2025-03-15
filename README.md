# DES Encryption Implementation

## Overview

![My Image](https://github.com/MrkFrcsl98/DES_algorithm/blob/main/ewpoierwewoepowepw.jpg?raw=true)

This project provides a C++ implementation of the Data Encryption Standard (DES) algorithm. DES is a symmetric-key block cipher that encrypts data in 64-bit blocks using a 56-bit key. Although DES is considered obsolete due to its vulnerability to modern attacks, this implementation serves as an educational tool to understand the principles of symmetric encryption and the workings of the DES algorithm.

## Requirements

- C++11 or later
- A C++ compiler (e.g., g++, clang++)

## How To Use

first extract the class from the namespace.

```cpp
using namespace DES;
```

then, create new instance of DES.

```cpp
DES_Encryption des;
```

define some data and key, data can be long any size, the key must be 8 bytes
```cpp
const std::string data("data");
const std::string key("12345678");
```

convert data to array type
```cpp
std::vector<std::uint8_t> byte_array = DES_Encryption::toByteArray(message);
```

convert data array to binary for encryption
```cpp
DES_Encryption::tBitStream binary_message = DES_Encryption::toBinary(byte_array);
```

encrypt
```cpp
DES_Encryption::tBitStream encrypted = DES.Encrypt(binary_message);
```

print encrypted result
```cpp
std::vector<std::uint8_t> toHex = DES_Encryption::binToHex(encrypted); // convert to hex array
std::string toString = DES_Encryption::toByteString(toHex); convert from array hex to string
std::cout << "Encrypted: " << toString << "\n";
```

decryption
```cpp
DES_Encryption::tBitStream decrypted = DES.Decrypt(encrypted);
```

print decrypted text
```cpp
std::vector<unsigned char> decryptedAscii = DES_Encryption::toAscii(decrypted);
std::string dAsciiString = DES_Encryption::toByteString(decryptedAscii);
std::cout << "Decrypted: "<< dAsciiString << "\n";
```

complete example
```cpp
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
            std::cout << "Decrypted: "<< dAsciiString << "\n";
```


![My Image](https://github.com/MrkFrcsl98/DES_algorithm/blob/main/fewafjewropiewrpewrww.jpg?raw=true)
```cpp
        // --------------------------------------
        //            DES BLOCK CIPHER
        // --------------------------------------
        // DATA-ENCRYPTION-STANDARD(DES) Cryptosystem
        //
        // The Data Encryption Standard (DES) is a symmetric block cipher that was widely used for
        // data encryption. Developed by IBM, DES operates on 64-bit blocks of plaintext and
        // utilizes a 56-bit key for encryption, derived from a 64-bit key where 8 bits are used for
        // parity checks.

        // DES employs a Feistel network structure, which divides the plaintext into two halves and
        // processes them through a series of operations over multiple rounds. Specifically, DES
        // performs 16 rounds of encryption, each using a unique subkey generated from the original
        // key through a key scheduling mechanism. This mechanism involves permutation and rotation
        // to ensure that each subkey is distinct, enhancing security.

        // During each round of encryption, the plaintext is split into a left half (L) and a right
        // half (R). The right half is expanded using a permutation to match the size of the subkey,
        // resulting in a 48-bit value. This expanded right half is then XORed with the subkey for
        // that round. The result is passed through a series of substitution boxes (S-boxes), which
        // perform a nonlinear transformation on the data. The output of the S-boxes is then
        // permuted using another permutation known as the P-box.

        // After processing, the left and right halves are swapped, and the process is repeated for
        // the next round. After the final round, the left and right halves are combined and passed
        // through a final permutation known as the Inverse Initial Permutation (IP-1) to produce
        // the ciphertext.

        // The strength of DES lies in its complexity and the multiple rounds it performs. With 16
        // rounds and a 56-bit key, there are a total of 2^56 possible keys, which was once
        // considered to make brute-force attacks impractical. However, due to advances in computing
        // power, DES is now regarded as insecure for modern encryption needs.

        // DES follows the principles of confusion and diffusion, as defined by the cryptographer
        // Claude Shannon. Confusion obscures the relationship between the plaintext and the
        // ciphertext, often achieved through substitution tables like the S-boxes. Diffusion
        // ensures that changes in the plaintext result in significant changes in the ciphertext,
        // which is accomplished through operations like permutation and mixing of bits. This
        // spreading effect is known as the avalanche effect, where a small change in the input
        // (such as flipping a single bit) leads to substantial changes in the output.

        // The "f" function is a crucial component of each round in the DES encryption process. It
        // takes a 32-bit input and a 48-bit key, performing various mathematical operations,
        // including permutations, substitutions, and XOR operations, to produce a 32-bit output.
        // The output of the "f" function is combined with the left half of the block, and the two
        // halves are then swapped.

        // It is important to note that during the encryption process, the left half (L0) is
        // modified by XORing it with the output of the "f" function, while the right half (R0)
        // remains unchanged until the swap occurs. This means that the output of the encryption
        // process (R1) is equal to R0.

        // The initial step in the encryption process is the Initial Permutation (IP), which
        // rearranges the input data (the 64-bit plaintext) by copying specific bits from one
        // position to another. This rearranging process is applied before the rounds of encryption
        // begin. After the final round, the final permutation (IP-1) is applied, effectively
        // restoring the data to its original order.

        // The inclusion of the initial permutation was primarily introduced for practical
        // electrical engineering reasons rather than cryptographic security. It addressed specific
        // challenges in data transfer within the chip but does not significantly impact the speed
        // or security of the algorithm.

        // To increase the complexity of DES, an expansion box is used, which takes a 32-bit input
        // (R) and produces a 48-bit output. Following this, the expanded input is XORed with a
        // subkey derived from the original key, adding another layer of complexity to the
        // encryption process.

        // The S-boxes are a critical part of the "f" function, with a total of 8 S-boxes in the DES
        // encryption process. Each S-box takes in 6 bits and outputs 4 bits, introducing
        // non-linearity to the algorithm and making it more resistant to attacks. The S-boxes can
        // be viewed as lookup tables, where the first 4 bits of the input select one of the 16
        // columns, and the last 2 bits select one of the 4 rows to determine the output value.

        // In 1990, researchers Adi Shamir and Eli Biham discovered a technique called differential
        // cryptanalysis, which exploits the structure of S-boxes to analyze the differences in
        // output when small changes are made to the input. This discovery highlighted
        // vulnerabilities in DES, further contributing to its decline in security for modern
        // applications.
```

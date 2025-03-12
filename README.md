# DES Encryption Implementation

## Overview

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

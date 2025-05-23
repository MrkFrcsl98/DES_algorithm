# DES & 3DES C++ Encryption Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![C++](https://img.shields.io/badge/language-C%2B%2B11%20%2B-blue)
![DES](https://img.shields.io/badge/algorithm-DES%20%2F%203DES-green)
![Modes](https://img.shields.io/badge/modes-ECB%2CCBC%2CCFB%2COFB%2CCTR-yellow)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()


---

## Contents

- [DES Algorithm Documentation & History](#des-algorithm-documentation--history)
- [Project Overview](#project-overview)
- [Features](#features)
- [Requirements](#requirements)
- [Operation Modes](#operation-modes)
- [Key and IV Generation](#key-and-iv-generation)
- [Usage](#usage)
- [Example](#example)
- [Screenshots](#screenshots)
- [License](#license)

---


## DES Algorithm Documentation & History

### DES Block Cipher Overview

The **Data Encryption Standard (DES)** is a symmetric-key block cipher that operates on 64-bit blocks of data using a 56-bit key (plus 8 parity bits). Developed by IBM in the 1970s and adopted as a U.S. federal standard in 1977, DES was the foundation of digital cryptography for decades. Although DES is now considered obsolete for secure communications, it remains a cornerstone for understanding block cipher design and symmetric encryption.

### DES Encryption Pipeline

#### 1. Initial Permutation (IP)

- The 64-bit plaintext block is subjected to a fixed permutation called the Initial Permutation (IP), designed for hardware efficiency.
- **Example:**  
  If the input is `plaintext[0..63]`, the output is a reordered sequence where each output bit is mapped from a specific input bit according to the IP table.

#### 2. Feistel Network Structure

DES uses a Feistel network with 16 rounds.  
Each round splits the block into left (L) and right (R) 32-bit halves:

```
L0 = IP_block[0..31]
R0 = IP_block[32..63]
```

For each round i (1 ≤ i ≤ 16):

```
Li = Ri-1
Ri = Li-1 XOR F(Ri-1, Ki)
```

Where:
- **F** is the round function (see below)
- **Ki** is the round subkey

#### 3. Round Function (F-function)

The F-function is central to DES security, introducing both confusion and diffusion:

- **Expansion (E-Box):**  
  The 32-bit right half is expanded to 48 bits by duplicating and permuting certain bits, according to the E-table:
  ```
  expanded_block[0..47] = ExpansionPermutation(Ri-1)
  ```
  This ensures each S-box input depends on multiple plaintext bits.

- **XOR with Subkey:**  
  The expanded block is XORed with the 48-bit round subkey:
  ```
  xored_block = expanded_block XOR Ki
  ```

- **Substitution (S-Boxes):**  
  The 48-bit block is divided into eight 6-bit chunks.  
  Each chunk is mapped through a specific S-box, producing a 4-bit output.  
  This yields a 32-bit output, dramatically increasing non-linearity.
  ```
  for i in 0..7:
      sbox_output[i] = Sbox[i](xored_block[i*6 : (i+1)*6])
  combined_sbox = concat(sbox_output[0..7]) // 32 bits
  ```

- **Permutation (P-Box):**  
  The combined S-box output is permuted to further diffuse the bits:
  ```
  permuted = PPermutation(combined_sbox)
  ```

#### 4. Swap and Repeat

- After each round, the left and right halves are swapped for the next round.
- After the 16th round, the halves are recombined as (R16, L16).

#### 5. Final Permutation (IP-1)

- The combined block is passed through the inverse of the initial permutation (IP-1), producing the final ciphertext.

---

### DES Key Schedule

- The original 64-bit key is reduced to 56 bits by discarding every 8th bit (parity).
- The 56-bit key is split into two 28-bit halves.
- For each round:
  - Each half is rotated left by 1 or 2 bits (depending on the round).
  - 48 bits are selected using a fixed permutation (PC-2) to form the subkey for that round.

---

### Triple DES (3DES)

**3DES** (“Triple DES”) enhances DES security by applying the DES cipher three times in sequence with three different keys:
```
Ciphertext = DES_encrypt(K3, DES_decrypt(K2, DES_encrypt(K1, Plaintext)))
```
- **3 independent keys**: 168-bit key strength
- Same block size and mode support as DES

---

## Example: DES Round Operations

Let’s walk through the operations for a single round:

**Input Block:**  
`plaintext_block[64] = [b0, b1, ..., b63]`

1. **Initial Permutation:**  
   `IP_block[64] = InitialPermutation(plaintext_block)`

2. **Split into Halves:**  
   ```
   L0[32] = IP_block[0..31]
   R0[32] = IP_block[32..63]
   ```

3. **Round 1:**  
   ```
   L1 = R0
   R1 = L0 XOR F(R0, K1)
   ```

4. **F-function Steps:**  
   ```
   expanded_R0[48] = ExpansionPermutation(R0)
   xored = expanded_R0 XOR K1
   sbox_out[32] = SBoxSubstitution(xored)
   permuted = PPermutation(sbox_out)
   ```

5. **Combine and Swap:**  
   After 16 rounds, final output is (R16, L16), which is then permuted using IP-1.

---

### DES Modes of Operation

This library supports all major block cipher modes, for both DES and TripleDES:
- **ECB** (Electronic Codebook)
- **CBC** (Cipher Block Chaining)
- **CFB** (Cipher Feedback)
- **OFB** (Output Feedback)
- **CTR** (Counter Mode)

Each mode provides different security properties and is suitable for various applications. All are implemented in `des.hpp` with a unified API.

---

### Key and IV Generation

For cryptographic safety and demonstration flexibility, this library includes secure key and IV generators:

- `DESUtils::GenerateKey()` — 8 bytes for DES
- `DESUtils::GenerateIV()` — 8 bytes for IV (for CBC/CFB/OFB/CTR)
- `DESUtils::GenerateTripleKey()` — 24 bytes for 3DES

---

## Project Overview

![DES Illustration](https://github.com/MrkFrcsl98/DES_algorithm/blob/main/ewpoierwewoepowepw.jpg?raw=true)

This project delivers a modern, header-only C++11 implementation of DES and 3DES algorithms, including all common block cipher modes and secure random key/IV generation.  
It’s ideal for cryptography education, experimentation, and understanding the inner workings of classic symmetric ciphers.

---

## Features

- Full DES & 3DES support with unified API
- ECB, CBC, CFB, OFB, CTR modes for both DES and 3DES
- Secure random key & IV generation
- PKCS7 padding for all modes
- Clean, educational code in a single header (`des.hpp`)
- Simple, modern C++ usage


---

## Requirements

- C++11 or later
- Standard C++ compiler (g++, clang++, MSVC)

---

## Operation Modes

- **ECB** (Electronic Codebook)
- **CBC** (Cipher Block Chaining)
- **CFB** (Cipher Feedback)
- **OFB** (Output Feedback)
- **CTR** (Counter Mode)

All modes are available for both DES and TripleDES with identical API.

---

## Key and IV Generation

```cpp
auto des_key    = DESUtils::GenerateKey();        // 8 bytes for DES
auto des_iv     = DESUtils::GenerateIV();         // 8 bytes for DES/3DES IV
auto tdes_key   = DESUtils::GenerateTripleKey();  // 24 bytes (3 * 8)
```

---

## Usage

### 1. Include the Header

```cpp
#include "des.hpp"
```

### 2. (Optional) Use the Namespace

```cpp
using namespace DES;
```

### 3. Encrypt and Decrypt

#### DES Example (CBC Mode)

```cpp
std::string plaintext = "this is a secret message...";
std::string key = "12345678"; // Must be 8 bytes
std::vector<bool> iv = detail::toBitVector("abcdefgh"); // 8 bytes

auto encrypted = DES::CBC::Encrypt(plaintext, key, iv);
auto decrypted = DES::CBC::Decrypt(encrypted.toString(), key, iv);

std::cout << "Encrypted (hex): " << encrypted.toHex() << "\n";
std::cout << "Decrypted: " << decrypted.toString() << "\n";
```

#### TripleDES Example (CFB Mode)

```cpp
std::string k1 = "12345678";
std::string k2 = "abcdefgh";
std::string k3 = "ABCDEFGH";
auto iv = detail::toBitVector("12345678");

auto enc = TripleDES::CFB::Encrypt(plaintext, k1, k2, k3, iv);
auto dec = TripleDES::CFB::Decrypt(enc.toString(), k1, k2, k3, iv);

std::cout << "3DES Encrypted (hex): " << enc.toHex() << "\n";
std::cout << "3DES Decrypted: " << dec.toString() << "\n";
```

#### Secure Key/IV Generation Example

```cpp
auto key_bytes = DESUtils::GenerateKey();
auto triple_key = DESUtils::GenerateTripleKey();
auto iv_bytes = DESUtils::GenerateIV();
```

---

## Example

```cpp
#include "des.hpp"
#include <iostream>
#include <iomanip>

int main() {
    using namespace DES;
    std::string plaintext = "Attack at dawn! This is a test message.";
    while (plaintext.size() % 8) plaintext += ".";

    auto des_key = DESUtils::GenerateKey();
    auto des_iv = DESUtils::GenerateIV();
    std::string key(des_key.begin(), des_key.end());
    std::string iv_str(des_iv.begin(), des_iv.end());
    std::vector<bool> iv = detail::toBitVector(iv_str);

    auto enc = DES::CBC::Encrypt(plaintext, key, iv);
    auto dec = DES::CBC::Decrypt(enc.toString(), key, iv);

    std::cout << "DES CBC Encrypted (hex): " << enc.toHex() << "\n";
    std::cout << "DES CBC Decrypted: " << dec.toString() << "\n";
}
```

---

## Screenshots

![DES Screenshot 1](https://github.com/MrkFrcsl98/DES_algorithm/blob/main/lpdsdspldpsldpsdsds.jpg?raw=true)
![DES Screenshot 2](https://github.com/MrkFrcsl98/DES_algorithm/blob/main/fewafjewropiewrpewrww.jpg?raw=true)

---

## License

This project is licensed under the MIT License.

---

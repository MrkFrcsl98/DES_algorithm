#include <chrono>
#include <string>
#include <vector>

#define _DES_ENCRYPTION_ALGORITHM_

namespace DES {

template <typename T>
class ByteHelper {
 public:
  explicit ByteHelper() noexcept {};
  ~ByteHelper() noexcept {};

  /**
   * @brief Convert data to binary
   *
   * @tparam _bT
   * @param _source source data
   * @return const _vectorT
   */
  template <typename _bT = unsigned char>
  inline static constexpr std::vector<T> toBinary(const std::vector<_bT>& _source) noexcept {
    std::vector<T> _binResult(_source.size() * 8);
    std::size_t counter{0};
    for (_bT c : _source)
      for (int i{7}; i >= 0; --i, counter++)
        _binResult[counter] = ((c & (1 << i)) ? 1 : 0);
    return _binResult;
  };

  /**
   * @brief convert to binary
   *
   * @tparam _bT
   * @param _source source data
   * @param _dest destination object
   */
  template <typename _bT = char>
  inline static void toBinary(const std::vector<_bT>& _source, std::vector<T>& _dest) noexcept {
    _dest = toBinary(_source);
  };

  /**
   * @brief convert to ascii
   *
   * @tparam _bT type of _source byte data type
   * @tparam _rT
   * @param _source data
   * @return const std::vector<_rT>
   */
  template <typename _bT = bool, typename _rT = unsigned char>
  inline static constexpr std::vector<_rT> toAscii(const std::vector<_bT>& _source) noexcept {
    if (_source.empty() || _source.size() % 8 != 0) [[unlikely]]
      return {};
    std::vector<_rT> result(_source.size() / 8);
    std::size_t counter{0};
    for (std::size_t i{0}; i < _source.size(); i += 8) {
      char c = 0;
      for (int j{0}; j < 8; ++j) {
        c <<= 1;
        if (_source[i + j] == 1)
          c |= 1;
      }
      result[counter++] = c;
    }
    return result;
  };

  /**
   * @brief convert to ascii
   *
   * @tparam _bT
   * @tparam _rT
   * @param _source source data
   * @param _dest destination object
   */
  template <typename _bT = bool, typename _rT = unsigned char>
  inline static void toAscii(const std::vector<_bT>& _source, std::vector<_rT>& _dest) noexcept {
    _dest = toAscii(_source);
  };

  /**
   * @brief convert data to hex
   *
   * @tparam _bT
   * @param _source
   * @return const std::vector<char>
   */
  template <typename _bT = bool>
  inline static constexpr std::vector<unsigned char> binToHex(
      const std::vector<_bT>& _source) noexcept {
    if (_source.empty() || _source.size() % 4 != 0) [[unlikely]]
      return {};
    std::vector<unsigned char> result;
    for (std::size_t i = 0; i < _source.size(); i += 4) {
      unsigned int hexValue = 0;
      for (int j = 0; j < 4; ++j) {
        hexValue <<= 1;
        if (_source[i + j] == 1) {
          hexValue |= 1;
        }
      }
      if (hexValue < 10) {
        result.push_back('0' + hexValue);
      } else {
        result.push_back('A' + (hexValue - 10));
      }
    }
    return result;
  };

  /**
   * @brief conver to hex
   *
   * @tparam _bT
   * @param _source
   * @param _dest
   */
  template <typename _bT = bool>
  inline static void binToHex(const std::vector<_bT>& _source,
                              std::vector<unsigned char>& _dest) noexcept {
    _dest = binToHex(_source);
  };

  /**
   * @brief convert from vector container to character sequence
   *
   * @tparam _bT
   * @param _source
   * @return const std::string
   */
  template <typename _bT = bool>
  inline static constexpr std::string toByteString(const std::vector<_bT>& _source) noexcept {
    if (_source.empty()) [[unlikely]]
      return "";
    std::string out;
    out.resize(_source.size());
    bool is_binary = true;
    for (const _bT b : _source)
      if (b != 1 && b != 0)
        is_binary = false;
    if (is_binary)
      for (const _bT b : _source)
        out += std::to_string(b);
    else
      for (const _bT b : _source)
        out += (char)b;
    return out;
  };

  /**
   * @brief convert from character sequence to vector object
   *
   * @tparam _bT
   * @param _source
   * @return const std::vector<_bT>
   */
  template <typename _bT = unsigned char>
  inline static constexpr std::vector<_bT> toByteVector(const std::string& _source) noexcept {
    if (_source.empty()) [[unlikely]]
      return {};
    std::vector<_bT> out(_source.size());
    std::size_t counter{0};
    for (const auto b : _source) {
      out[counter++] = b;
    }
    return out;
  };
};

/**
 * @brief DES_Encryption Class
 * Encrypt data using DES Algorithm.
 * DES is no longer considered secure as algorithm since 1990s, is suggested to
 * use modern standard algorithms such as AES(Advanced-Encryption-Standard).
 * DES is a block cipher operating on blocks of fixed size(64-bits).
 * Operates on Claude Shannon principle, stating that a good algorithm must
 * implement good diffusion and confusion mechanisms, diffusion ensures that
 * a change in a single bit affects many others, confusion obfuscates the relationship
 * between the plaintext and ciphertext.
 * DES start the process by generating the required 16-rounds subkeys, each subkey
 * is different, and used within the specific round.
 * AES incorporates a total of 16 rounds, during each round, other operations such
 * as permutation and substitution are applied on each 64-bit block of data.
 * Uses 8 4*16 Matrix vector Substitution-Boxes to provide diffusion, these 4*16 S-boxes
 * take a 6-bit input and generates a 4-bit output.
 * The initial key(main key) of encryption is 8-bytes or 64-bit(mandatory), 8-bits are used
 * for parity checking, while the remaining 56-bits are the actual key.
 * there are a total of 1^56 number of possible keys, decades ago this number would have
 * been very difficult if not impossible to break, but nowdays, with modern computing power
 * is become very easy. This was the main reason of DES becoming obsolete.
 * The 56-bit key is then split into 2 halves(left,right), each 28-bits long and are
 * processed to generate the 16 subkeys.
 * Additional padding(0s) is added to the data to make sure it matches the key size.
 *
 */
class DES_Encryption : public ByteHelper<bool> {
#define SBSZ (std::uint16_t)0x08  // number of substitution boxes
#define SBR (std::uint16_t)0x04   // number of rows within each S-box
#define SBC (std::uint16_t)0x10   // number of columns within each S-box

  typedef std::vector<bool> _vectorT;  // type definition of container used for bit manipulation
  typedef std::vector<std::vector<bool>> _mVectorT;

  /**
   * @brief Structure containing left and right halves.
   *
   */
  struct _Halves {
    _vectorT l{};
    _vectorT r{};
    __attribute__((cold)) _Halves(const std::uint16_t _s) noexcept {
      l.resize(_s);
      r.resize(_s);
    };
    __attribute__((cold)) _Halves(const _Halves& _copy) noexcept {
      l.resize(_copy.l.size());
      r.resize(_copy.r.size());
      l = _copy.l;
      r = _copy.r;
    };
    ~_Halves() noexcept {
      l.clear();
      r.clear();
    };
  };

 public:
  typedef std::vector<bool> tBitStream;

  std::uint32_t id = 0;  // used only to identify the object, used within copy/move constructors

  /**
   * @brief Construct a new des encryption object
   *
   */
  explicit DES_Encryption(void) = delete;

  /**
   * @brief Construct a new des encryption object and copy from _copy
   *
   * @param _copy
   */
  DES_Encryption(const DES_Encryption& _copy) noexcept {
    this->_initObjectState();
    if (*this != _copy) [[likely]] {
      this->__subkeys = _copy.getSubkeys();
    }
  };

  /**
   * @brief Construct a new des encryption object and move data from _copy
   *
   * @param _copy
   */
  DES_Encryption(DES_Encryption&& _copy) noexcept {
    this->_initObjectState();
    if (*this != _copy) [[likely]] {
      this->__subkeys = std::move(_copy.getSubkeys());
    }
  };

  inline const bool operator!=(const DES_Encryption& _copy) noexcept {
    return (this->id != _copy.id);
  };

  /**
   * @brief Destroy the des encryption object
   *
   */
  ~DES_Encryption(void) noexcept {
    if (this->__subkeys.size() > 0) {
      for (_vectorT v : this->__subkeys) {
        v.clear();
      }
    }
  };

  /**
   * @brief Construct a new des encryption object with key input.
   * 16-rounds Subkeys are generated in this constructor.
   *
   * @param _key
   */
  explicit DES_Encryption(const std::string& _key) noexcept { this->_initialization(_key); };

  /**
   * @brief Get the Subkeys vector
   *
   * @return const _mVectorT&
   */
  inline const _mVectorT& getSubkeys() const noexcept { return this->__subkeys; };

  /**
   * @brief Encryption function. The first operation after key scheduling, is
   * the padding of the data to 64-bit.
   * This is mandatory since DES works on 64-bit blocks of fixed size data and
   * the data must be a multiple of 64-bits, if the padding is not applied, the
   * algorithm will crash.
   *
   *
   *
   * @param _source input
   * @return const _vectorT
   */
  const _vectorT Encrypt(const _vectorT& _source) {
    _vectorT _out;
    if (_source.size() == 0) [[unlikely]]
      return _out;
    _vectorT source(_source);
    this->_PKCS7PaddingInjection(source);
    for (std::size_t i{0}; i < source.size(); i += this->_KeySize) {
      _vectorT _block(source.begin() + i, source.begin() + i + this->_KeySize);
      _vectorT _encryptedBlock(this->_KeySize);
      this->_64bitBlockETransformation(_block, _encryptedBlock);
      _out.insert(_out.end(), _encryptedBlock.begin(), _encryptedBlock.end());
    }
    return _out;
  };

  const _vectorT Encrypt(const std::string& _source) {
    std::vector<std::uint8_t> byte_array = DES_Encryption::toByteVector(_source);  // convert string message to vector type
    DES_Encryption::tBitStream binary_message = DES_Encryption::toBinary(byte_array);  // now convert to binary, tBitStream is a type
    return this->Encrypt(binary_message);
  };

  /**
   * @brief Encrypt _source and store result into _dest
   *
   * @param _source
   * @param _dest
   */
  void Encrypt(const _vectorT& _source, _vectorT& _dest) { _dest = this->Encrypt(_source); };

  /**
   * @brief Decrypt _source
   *
   * @param _source
   * @return const _vectorT
   */
  const _vectorT Decrypt(const _vectorT& _source) {
    _vectorT _out;
    if (_source.size() == 0) [[unlikely]]
      return _out;
    _vectorT source(_source);
    for (std::size_t i{0}; i < source.size(); i += this->_KeySize) {
      _vectorT _block(source.begin() + i, source.begin() + i + this->_KeySize);
      _vectorT _decryptedBlock(this->_KeySize);
      this->_64bitBlockDTransformation(_block, _decryptedBlock);
      _out.insert(_out.end(), _decryptedBlock.begin(), _decryptedBlock.end());
    }
    this->_PKCS7PaddingEjection(_out);
    return _out;
  };

  /**
   * @brief Decrypt _source and store into _dest
   *
   * @param _source
   * @param _dest
   */
  void Decrypt(const _vectorT& _source, _vectorT& _dest) { _dest = this->Decrypt(_source); };

 private:
  __attribute__((cold, always_inline)) inline void _PKCS7PaddingInjection(
      _vectorT& _source) noexcept {
    if (_source.empty()) [[unlikely]]
      return;
    const std::uint8_t padv{
        static_cast<std::uint8_t>(this->_KeySize - (_source.size() % this->_KeySize))};
    const std::uint8_t padding_size = padv == this->_KeySize ? (std::uint8_t)this->_KeySize : padv;
    for (std::uint8_t i = 0; i < padding_size; ++i)
      _source.push_back(static_cast<std::uint8_t>(padding_size));
  };

  __attribute__((cold, always_inline)) inline void _PKCS7PaddingEjection(
      _vectorT& _source) noexcept {
    if (_source.empty()) [[unlikely]]
      return;
    std::vector<unsigned char> to_string_bytes(toAscii(_source));
    const std::uint8_t back{to_string_bytes.back()};
    while (!to_string_bytes.empty() && ((int)to_string_bytes.back() == back)) {
      to_string_bytes.pop_back();
    }
    _source = toBinary(to_string_bytes);
  };

  __attribute__((cold, always_inline)) inline void _initialization(const std::string& _key) {
    if (_key.empty()) [[unlikely]]
      throw std::invalid_argument("Invalid key value!");
    this->_initObjectState();
    this->_generateSubkeys(this->_convertKeyStr2Binary(_key.size() > 8 ? _key.substr(0, 8) : _key));
  };

  /**
   * @brief Generate Subkeys for 16 rounds of encryption.
   * Initial permutation(IP) is applied on _key, then the permuted key(pk)
   * is split into 2 halves(L0, R0) each 28-bit long.
   * After key split, a 16-rounds mechanism applies key rotation on R0 and
   * generates a new subkey for current round by applying compression permutation(CP)
   * on the 2 halves(L0, R0).
   * The PC1 table is used for the initial permutation(IP) function.
   * The initial permutation(IP) function takes the 56-bit key and the Permutation Choice(PC1)
   * S-table to apply the permutation on the key bits, this provides diffusion which is essential
   * part of DES. The PC1 table is a 56-bit table, key size must be exactly the table size.
   * After the initial permutation operation, the permuted key(PK) is split into two halves(L, R).
   * Each half is exactly 28-bits long, the 2 sides(L, R) are then subjectect to a series of
   * rotations and compression permutation operations to generate the final subkey.
   * The halves are subjected to 16 rounds of rotation/CP. The resulting subkey for the
   * current round is stored in the subkeys array.
   *
   * @param _vectorT& 64-bit key(MAIN)
   *
   */
  __attribute__((stack_protect)) void _generateSubkeys(const _vectorT& _key) {
    if (_key.size() != this->_KeySize) [[unlikely]] {
      throw std::range_error(
          "_key size do not match max bits allowed, _key size = " + std::to_string(_key.size()) +
          ", max allowed = " + std::to_string(this->_KeyBits));
    }
    const _vectorT pk(this->_initPermutation(_key));
    this->_keyScheduling(pk);
  };

  /**
   * @brief Key scheduling process, partition, rotation and compressionPermutation.
   * the permuted 56-bit key is split into 2 halves(L, R).
   * The operation enters then a 16-round iteration, where the halves are then
   * rotated and a compression permutation function is applied to generate
   * the subkey for the current round, the compressionPermutation function
   * uses the PC2 table to generate the output, the subkey is then propagated to the
   * subkey array.
   * The final subkey will have a size of 48-bits.
   *
   * @param _permuted_key
   */
  __attribute__((cold, always_inline)) inline void _keyScheduling(const _vectorT& _permuted_key) {
    struct _Halves halves(this->_28bitKeyPartition(_permuted_key));
    for (std::uint16_t r{0}; r < this->_Rounds; ++r) {
      this->_keyRotation(halves, r);
      this->__subkeys.push_back(this->_compressionPermutation(halves));
    }
  };

  /**
   * @brief generate id for object id
   *
   */
  __attribute__((cold, always_inline)) inline void _initObjectState(void) noexcept {
    if (this->id == 0) [[likely]] {
      std::uint64_t state = std::time(nullptr);
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      state = (10000000) + (state % (UINT32_MAX - 10000000 + 1));
      this->id = state;
    }
  };

  /**
   * @brief 64-bit block transformation. Handle block permutation using IP-table,
   * the current block of data is permuted using the IP permutation table, then
   * is partitioned in 2 32-bit halves(L,R), the first 32 bits are stored into L,
   * while the remaining 32 from 32 to 64 are stored into R.
   * After block permutation and partition, the process enters a 16 round iteration
   * where the halves are expanded, mixed, etc...
   * The first operation within the 16 rounds, is the expansion permutation(E), which
   * takes the R half, and generates a new 48-bit expanded bitstream based on the R half
   * content and E-table content.
   * After expansion permutation, the new expanded value are mixed(XORed) with the
   * bits from the current round subkey.
   * After mixing, the new mixed bitstream is passed through a substitution function,
   * involving S-boxes to calculate the substitution bits.
   * After substitution, another Permutation(P) is applied on the substituted bits,
   * this Permutation(P) uses the IP(initial-permutation) table to calculate the result,
   * the result of the Permutation function is a 32-bit value, which is the new value for
   * the R-half block.
   * The newly permuted bitstream is then XORed with the L-half block to generate R1
   * and then the left and right halves are swapped.
   * After halves swapping, L and R are combined, and the combined bitstream goes through
   * a final permutation(P-1), which uses the inverse IP-table, and generates the final
   * output(ciphertext).
   *
   * @param _64bitBlock
   * @param _subkeys
   * @param _output
   */
  __attribute__((hot, stack_protect)) void _64bitBlockETransformation(const _vectorT& _64bitBlock,
                                                                      _vectorT& _output) {
    if (_64bitBlock.size() != 64) [[unlikely]] {
      throw std::invalid_argument("block size must be multiple of 64!");
    }
    _vectorT _block_permutation = this->_64bitBlockPermutation(_64bitBlock);
    if (_block_permutation.size() != _KeySize) [[unlikely]] {
      throw std::invalid_argument("P-Block must be in 64-bit size!");
    }
    struct _Halves halves = this->_64bitBlockPartition(_block_permutation);
    for (std::uint16_t r{0}; r < this->_Rounds; ++r) {
      if (halves.r.size() != _HISize) [[unlikely]] {
        throw std::invalid_argument("R0 half size error, not a 32-bit block!");
      }
      _vectorT _expanded(this->_expansionPermutation(halves.r));
      _vectorT _mixed(this->_keyMixing(_expanded, r));
      _vectorT _sBoxOut(this->_sBoxSubstitution(_mixed));
      _vectorT _permuted(this->_pPermutation(_sBoxOut));
      _vectorT _R1(_HISize);
      for (std::uint16_t i{0}; i < _R1.size(); ++i) {
        _R1[i] = halves.l[i] ^ _permuted[i];
      }
      halves.l = halves.r;
      halves.r = _R1;
    }
    _vectorT _combined(this->_KeySize);
    for (std::uint16_t i{0}; i < _combined.size() / 2; ++i) {
      _combined[i] = halves.r[i];
      _combined[i + (_combined.size() / 2)] = halves.l[i];
    }
    _output = this->_finalPermutation(_combined);
  };

  __attribute__((hot, stack_protect)) void _64bitBlockDTransformation(const _vectorT& _64bitBlock,
                                                                      _vectorT& _output) {
    if (_64bitBlock.size() != 64) [[unlikely]]
      throw std::invalid_argument("block size invalid!");
    _vectorT _permuted_input = this->_64bitBlockPermutation(_64bitBlock);
    struct _Halves halves = this->_64bitBlockPartition(_permuted_input);
    for (std::uint16_t r = this->_Rounds - 1; r < this->_Rounds; --r) {
      _vectorT _expanded(this->_expansionPermutation(halves.r));
      _vectorT _mixed(this->_keyMixing(_expanded, r));
      _vectorT _sBoxOut(this->_sBoxSubstitution(_mixed));
      _vectorT _permuted(this->_pPermutation(_sBoxOut));
      _vectorT _R1(this->_KeySize / 2);
      for (std::uint16_t i{0}; i < _R1.size(); ++i) {
        _R1[i] = halves.l[i] ^ _permuted[i];
      }
      halves.l = halves.r;
      halves.r = _R1;
    }
    _vectorT _combined(this->_KeySize);
    for (std::uint16_t i{0}; i < _combined.size() / 2; ++i) {
      _combined[i] = halves.r[i];
      _combined[i + (_combined.size() / 2)] = halves.l[i];
    }
    _output = this->_finalPermutation(_combined);
  };

  __attribute__((hot, always_inline)) inline const struct _Halves _64bitBlockPartition(
      const _vectorT& _block) noexcept {
    struct _Halves halves(_HISize);
    for (std::uint16_t i{0}; i < halves.l.size(); ++i) {
      halves.l[i] = _block[i];
      halves.r[i] = _block[i + halves.l.size()];
    }
    return halves;
  };

  __attribute__((hot, always_inline)) inline const _vectorT _64bitBlockPermutation(
      const _vectorT& _block) noexcept {
    _vectorT _block_permutation(this->_KeySize);
    for (std::uint16_t i{0}; i < this->_KeySize; ++i) {
      _block_permutation[i] = _block[this->_IP[i] - 1];
    }
    return _block_permutation;
  };

  __attribute__((hot, always_inline)) inline void _keyRotation(struct _Halves& _halves,
                                                               const std::uint16_t _round) {
    if (_round >= std::size(this->_SHIFTS))
      throw std::invalid_argument("_round value is invalid!");
    std::uint16_t _shift{this->_SHIFTS[_round]};
    std::rotate(_halves.l.begin(), _halves.l.begin() + _shift, _halves.l.end());
    std::rotate(_halves.r.begin(), _halves.r.begin() + _shift, _halves.r.end());
  };

  __attribute__((cold, always_inline)) inline _vectorT _initPermutation(
      const _vectorT& _key) noexcept {
    _vectorT _permuted_keys(this->_KeyBits);
    for (std::uint16_t i{0}; i < this->_KeyBits; ++i) {
      _permuted_keys[i] = _key[this->_PC1[i] - 1];
    }
    return _permuted_keys;
  };

  __attribute__((cold, always_inline)) inline struct _Halves _28bitKeyPartition(
      const _vectorT& _pk) noexcept {
    struct _Halves _h(this->_HKSize);
    for (std::uint16_t i{0}; i < this->_HKSize; ++i) {
      _h.l[i] = _pk[i];
      _h.r[i] = _pk[i + this->_HKSize];
    }
    return _h;
  };

  __attribute__((hot, always_inline, stack_protect)) inline const _vectorT _compressionPermutation(
      const struct _Halves& _halves) noexcept {
    _vectorT _subkey(this->_SKSize);
    for (std::uint16_t i{0}; i < _subkey.size(); ++i) {
      _subkey[i] =
          (this->_PC2[i] <= 28) ? _halves.l[this->_PC2[i] - 1] : _halves.r[this->_PC2[i] - 29];
    }
    return (const _vectorT)_subkey;
  };

  __attribute__((hot, always_inline, stack_protect)) inline const _vectorT _expansionPermutation(
      const _vectorT& _r) noexcept {
    _vectorT _expanded(this->_SKSize);
    for (std::uint16_t i{0}; i < _expanded.size(); ++i) {
      _expanded[i] = _r[this->_E[i] - 1];
    }
    return _expanded;
  };

  __attribute__((hot, always_inline, stack_protect)) inline const _vectorT _keyMixing(
      const _vectorT& _expanded,
      const std::uint16_t _round) noexcept {
    _vectorT _mixed(this->_SKSize);
    for (std::uint16_t i{0}; i < this->_SKSize; ++i) {
      _mixed[i] = _expanded[i] ^ this->__subkeys[_round][i];
    }
    return _mixed;
  };

  __attribute__((hot, stack_protect)) const _vectorT
  _sBoxSubstitution(const _vectorT& _mixed) noexcept {
    _vectorT _out(_HISize);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnarrowing"
    for (std::uint16_t i{0}; i < 8; ++i) {
      std::uint16_t _row{(_mixed[i * 8] << 1) | _mixed[i * 6 + 5]};
      std::uint16_t _col{(_mixed[i * 6 + 1] << 3) | (_mixed[i * 6 + 2] << 2) |
                         (_mixed[i * 6 + 3] << 1) | (_mixed[i * 6 + 4])};
      std::uint16_t _sboxOut{this->_S_BOX[i][_row][_col]};
      for (std::uint16_t j{0}; j < 4; ++j) {
        _out[i * 4 + j] = (_sboxOut >> (3 - j)) & 1;
      }
    }
#pragma GCC diagnostic pop
    return _out;
  };

  __attribute__((hot, always_inline, stack_protect)) inline const _vectorT _pPermutation(
      const _vectorT& _input) noexcept {
    _vectorT _out(_HISize);
    for (std::uint16_t i{0}; i < _out.size(); ++i) {
      _out[i] = _input[this->_IP[i] - 1];
    }
    return _out;
  };

  __attribute__((hot, always_inline)) inline const _vectorT _finalPermutation(
      const _vectorT& _combined) noexcept {
    _vectorT _out(_KeySize);
    for (std::uint16_t i{0}; i < _out.size(); ++i) {
      _out[i] = _combined[this->_IP_INV[i] - 1];
    }
    return _out;
  };

  __attribute__((cold)) inline const _vectorT _convertKeyStr2Binary(
      const std::string& _key) noexcept {
    _vectorT _keyResult(this->_KeySize);
    for (std::size_t i{0}; i < _key.length(); ++i) {
      unsigned char ch = static_cast<unsigned char>(_key[i]);
      for (int j{7}; j >= 0; --j) {
        _keyResult[i * 8 + j] = (ch >> j) & 1;
      }
    }
    return _keyResult;
  }

  _mVectorT __subkeys;

  const std::uint16_t _Rounds = 0b0010000u;
  const std::uint16_t _KeySize = 0b01000000u;             // 64-bits
  const std::uint16_t _ParityBits = 0b00001000u;          // 8-bits
  const std::uint16_t _KeyBits = _KeySize - _ParityBits;  // 56-bits
  const std::uint16_t _BlockSize = 0b01000000u;           // 64-bits data block size
  const std::uint16_t _SKSize = 0b00110000u;              // 48-bits subkey size
  const std::uint16_t _HISize = 0b00100000u;              // 32-bits permuted input size
  const std::uint16_t _HKSize = 0b00011100u;              // 28-bits permuted key size

  const std::uint16_t _S_BOX[SBSZ][SBR][SBC] = {
      {{0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7},
       {0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1, 0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8},
       {0x4, 0x1, 0xE, 0x8, 0xD, 0x6, 0x2, 0xB, 0xF, 0xC, 0x9, 0x7, 0x3, 0xA, 0x5, 0x0},
       {0xF, 0x2, 0x8, 0xE, 0x6, 0xB, 0x1, 0x3, 0x4, 0x9, 0x7, 0xD, 0xA, 0x0, 0x5, 0xC}},
      {{0xF, 0x1, 0x8, 0xE, 0x6, 0xB, 0x3, 0x4, 0x9, 0x7, 0x2, 0xD, 0x0, 0x5, 0xA, 0xC},
       {0x3, 0xD, 0x4, 0x7, 0xF, 0x2, 0x8, 0xE, 0xC, 0x0, 0x1, 0xA, 0x6, 0x9, 0xB, 0x5},
       {0x0, 0xE, 0x7, 0xB, 0xA, 0x4, 0xD, 0x1, 0x5, 0x8, 0xC, 0x6, 0x9, 0x3, 0x2, 0xF},
       {0xD, 0x8, 0xA, 0x1, 0x3, 0xF, 0x4, 0x2, 0xB, 0x6, 0x7, 0xC, 0x0, 0x5, 0xE, 0x9}},
      {{0xA, 0x0, 0x9, 0xE, 0x6, 0x3, 0xF, 0x5, 0x1, 0xD, 0x2, 0x8, 0x4, 0x7, 0x6, 0xB},
       {0xD, 0x7, 0x0, 0x9, 0x3, 0x4, 0x6, 0xA, 0x2, 0x8, 0x5, 0xE, 0xC, 0xB, 0xF, 0x1},
       {0xD, 0x6, 0x4, 0x9, 0x8, 0xF, 0x3, 0x0, 0xB, 0x1, 0x2, 0xC, 0x5, 0xA, 0xE, 0x7},
       {0x1, 0xA, 0xD, 0x0, 0x6, 0x9, 0x8, 0x7, 0x4, 0xF, 0xE, 0x3, 0xB, 0x5, 0x2, 0xC}},
      {{0x7, 0xD, 0xE, 0x3, 0x0, 0x6, 0x9, 0xA, 0x1, 0x2, 0x8, 0x5, 0xB, 0xC, 0x4, 0xF},
       {0xD, 0x8, 0xB, 0x5, 0x6, 0xF, 0x0, 0x3, 0x4, 0x7, 0x2, 0xC, 0x1, 0xA, 0xE, 0x9},
       {0xA, 0x6, 0x9, 0x0, 0xC, 0xB, 0x7, 0xD, 0xF, 0x1, 0x3, 0xE, 0x5, 0x2, 0x4, 0x8},
       {0x3, 0xF, 0x0, 0x6, 0xA, 0x1, 0xD, 0x8, 0x9, 0x4, 0x5, 0xB, 0xC, 0x7, 0x2, 0xE}},
      {{0x2, 0xC, 0x4, 0x1, 0x7, 0xA, 0xB, 0x6, 0x9, 0x5, 0x3, 0xE, 0x0, 0xF, 0xD, 0x8},
       {0x4, 0x2, 0x1, 0xB, 0xA, 0xD, 0x7, 0x8, 0xF, 0x9, 0xC, 0x5, 0x6, 0x3, 0x0, 0xE},
       {0xB, 0x8, 0xC, 0x7, 0x1, 0xE, 0x2, 0xD, 0x6, 0xF, 0x0, 0x9, 0xA, 0x4, 0x5, 0x3},
       {0xC, 0x1, 0xA, 0xF, 0x9, 0x2, 0x6, 0x8, 0x0, 0xD, 0x3, 0x4, 0xE, 0x7, 0x5, 0xB}},
      {{0xC, 0x1, 0xA, 0xF, 0x9, 0x2, 0x6, 0x8, 0x0, 0xD, 0x3, 0x4, 0xE, 0x7, 0x5, 0xB},
       {0xA, 0xF, 0x4, 0x2, 0x1, 0x7, 0x6, 0xB, 0xD, 0x9, 0x0, 0xE, 0x3, 0x5, 0xC, 0x8},
       {0x9, 0xE, 0xF, 0x5, 0x2, 0x8, 0xC, 0x3, 0x7, 0x0, 0x4, 0xA, 0x1, 0xD, 0xB, 0x6},
       {0x4, 0x3, 0x2, 0xC, 0x1, 0xA, 0xF, 0x9, 0xE, 0x7, 0x5, 0xB, 0x6, 0x8, 0x0, 0xD}},
      {{0x4, 0xB, 0x2, 0xE, 0xF, 0x0, 0x8, 0xD, 0x3, 0xC, 0x9, 0x7, 0x5, 0xA, 0x6, 0x1},
       {0xD, 0x0, 0xB, 0x7, 0x4, 0x9, 0x1, 0xA, 0xE, 0x3, 0x5, 0xC, 0x2, 0xF, 0x8, 0x6},
       {0x1, 0x4, 0xB, 0xD, 0xC, 0x3, 0x7, 0xE, 0xA, 0xF, 0x6, 0x8, 0x0, 0x5, 0x9, 0x2},
       {0x6, 0x1, 0x4, 0xB, 0xD, 0xC, 0x3, 0x7, 0xE, 0xA, 0xF, 0x8, 0x0, 0x5, 0x9, 0x2}},
      {{0xD, 0x2, 0x8, 0x4, 0x6, 0xF, 0xB, 0x1, 0xA, 0x9, 0x3, 0xE, 0x5, 0x0, 0xC, 0x7},
       {0x1, 0xF, 0xD, 0x8, 0xA, 0x3, 0x7, 0x4, 0xC, 0x5, 0x6, 0xB, 0x0, 0xE, 0x9, 0x2},
       {0x7, 0xB, 0x4, 0x1, 0x9, 0xC, 0xE, 0x2, 0x0, 0x6, 0xA, 0xD, 0xF, 0x3, 0x5, 0x8},
       {0x2, 0x1, 0xE, 0x7, 0x4, 0xA, 0x8, 0xD, 0xF, 0xC, 0x9, 0x0, 0x3, 0x5, 0x6, 0xB}}};

  const std::uint16_t _PC1[56] = {
      0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12,
      0x0A, 0x02, 0x3B, 0x33, 0x2B, 0x23, 0x1B, 0x13, 0x0B, 0x03, 0x3C, 0x34, 0x2C, 0x24,
      0x3F, 0x37, 0x2F, 0x27, 0x1F, 0x17, 0x0F, 0x07, 0x3E, 0x36, 0x2E, 0x26, 0x1E, 0x16,
      0x0E, 0x06, 0x3D, 0x35, 0x2D, 0x25, 0x1D, 0x15, 0x0D, 0x05, 0x1C, 0x14, 0x0C, 0x04};

  const std::uint16_t _PC2[48] = {0xE,  0x11, 0xB,  0x18, 0x1,  0x5,  0x3,  0x1C, 0xF,  0x6,
                                  0x15, 0xA,  0x17, 0x13, 0xC,  0x4,  0x1A, 0x8,  0x10, 0x7,
                                  0x1B, 0x14, 0xD,  0x2,  0x29, 0x18, 0x25, 0x1E, 0x3,  0x2E,
                                  0xA,  0xD,  0xF,  0x2,  0x8,  0x2F, 0xC,  0x6,  0x1,  0x27,
                                  0x5,  0x1D, 0x2C, 0x26, 0x24, 0xB,  0x19, 0x1C};

  const std::uint16_t _SHIFTS[16] = {0x1, 0x1, 0x2, 0x2, 0x2, 0x2, 0x1, 0x2,
                                     0x2, 0x2, 0x2, 0x2, 0x1, 0x2, 0x2, 0x1};

  const std::uint16_t _IP[64] = {0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12, 0x0A, 0x02, 0x3C, 0x34, 0x2C,
                                 0x24, 0x1C, 0x14, 0x0C, 0x04, 0x3E, 0x36, 0x2E, 0x26, 0x1E, 0x16,
                                 0x0E, 0x06, 0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08, 0x39,
                                 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01, 0x3B, 0x33, 0x2B, 0x23,
                                 0x1B, 0x13, 0x0B, 0x03, 0x3D, 0x35, 0x2D, 0x25, 0x1D, 0x15, 0x0D,
                                 0x05, 0x3F, 0x37, 0x2F, 0x27, 0x1F, 0x17, 0x0F, 0x07};

  const std::uint16_t _E[48] = {0x20, 0x1,  0x2,  0x3,  0x4,  0x5,  0x4,  0x5,  0x6,  0x7,
                                0x8,  0x9,  0x8,  0x9,  0xA,  0xB,  0xC,  0xD,  0xC,  0xD,
                                0xE,  0xF,  0x10, 0x11, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x18, 0x19, 0x1A, 0x1B,
                                0x1C, 0x1D, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x1};

  const std::uint16_t _IP_INV[64] = {
      0x28, 0x8, 0x30, 0x10, 0x38, 0x18, 0x40, 0x20, 0x27, 0x7, 0x2F, 0xF, 0x37, 0x17, 0x3F, 0x1F,
      0x26, 0x6, 0x2E, 0xE,  0x36, 0x16, 0x3E, 0x1E, 0x25, 0x5, 0x2D, 0xD, 0x35, 0x15, 0x3D, 0x1D,
      0x24, 0x4, 0x2C, 0xC,  0x34, 0x14, 0x3C, 0x1C, 0x23, 0x3, 0x2B, 0xB, 0x33, 0x13, 0x3B, 0x1B,
      0x22, 0x2, 0x2A, 0xA,  0x32, 0x12, 0x3A, 0x1A, 0x21, 0x1, 0x29, 0x9, 0x31, 0x11, 0x39, 0x19};

#ifdef SBSZ
#undef SBSZ
#endif
#ifdef SBR
#undef SBR
#endif
#ifdef SBC
#undef SBC
#endif
};
};  // namespace DES


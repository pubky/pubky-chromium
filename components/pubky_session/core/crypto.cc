// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// Calls C libraries (BoringSSL, BLAKE3, TweetNaCl) that take raw pointers.
#pragma allow_unsafe_buffers
#endif

#include "components/pubky_session/core/crypto.h"

#include <string.h>

#include <vector>

#include "base/check.h"
#include "base/check_op.h"
#include "third_party/blake3/src/blake3.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/hpke.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/rand.h"

extern "C" {
#include "third_party/tweetnacl/src/tweetnacl.h"

// TweetNaCl's randomness hook, renamed in //third_party/tweetnacl/BUILD.gn.
// Only key generation functions call it; Pubky uses none of them.
void pubky_tweetnacl_randombytes(unsigned char* out, unsigned long long len) {
  RAND_bytes(out, static_cast<size_t>(len));
}
}

namespace pubky_session {

namespace {

constexpr char kZ32Alphabet[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
constexpr size_t kZ32Length = 52;
constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Domain separation for HPKE relay channel IDs.
constexpr char kHpkeChannelDomain[] = "pubky-grant-relay-channel-v1";

// Includes the terminating NUL, which is part of the wire prefix.
constexpr char kHpkeWirePrefix[] = "pubky-hpke-v1";
constexpr size_t kHpkeWirePrefixSize = sizeof(kHpkeWirePrefix);
constexpr char kHpkeInfo[] = "pubky-grant-approval-hpke-v1";
constexpr size_t kHpkeEncappedKeySize = 32;

constexpr size_t kSecretBoxNonceSize = 24;
constexpr size_t kSecretBoxTagSize = 16;

const uint8_t* Bytes(std::string_view text) {
  return reinterpret_cast<const uint8_t*>(text.data());
}

int AlphabetIndex(const char* alphabet, size_t size, char character) {
  for (size_t i = 0; i < size; ++i) {
    if (alphabet[i] == character) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

}  // namespace

std::string EncodeZ32(const Key& key) {
  std::string out;
  out.reserve(kZ32Length);
  uint32_t buffer = 0;
  int bits = 0;
  for (uint8_t byte : key) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push_back(kZ32Alphabet[(buffer >> bits) & 31]);
    }
    buffer &= (1u << bits) - 1;
  }
  if (bits > 0) {
    out.push_back(kZ32Alphabet[(buffer << (5 - bits)) & 31]);
  }
  return out;
}

std::optional<Key> DecodeZ32(std::string_view text) {
  if (text.size() != kZ32Length) {
    return std::nullopt;
  }
  Key key{};
  size_t output = 0;
  uint32_t buffer = 0;
  int bits = 0;
  for (char character : text) {
    const int value = AlphabetIndex(kZ32Alphabet, 32, character);
    if (value < 0) {
      return std::nullopt;
    }
    buffer = (buffer << 5) | static_cast<uint32_t>(value);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (output == kKeySize) {
        return std::nullopt;
      }
      key[output++] = static_cast<uint8_t>(buffer >> bits);
      buffer &= (1u << bits) - 1;
    }
  }
  // 52 characters carry 260 bits; the last 4 must be zero.
  if (output != kKeySize || buffer != 0) {
    return std::nullopt;
  }
  return key;
}

std::string Base64UrlEncode(std::string_view bytes) {
  std::string out;
  out.reserve((bytes.size() * 4 + 2) / 3);
  uint32_t buffer = 0;
  int bits = 0;
  for (char c : bytes) {
    buffer = (buffer << 8) | static_cast<uint8_t>(c);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(kBase64UrlAlphabet[(buffer >> bits) & 63]);
    }
    buffer &= (1u << bits) - 1;
  }
  if (bits > 0) {
    out.push_back(kBase64UrlAlphabet[(buffer << (6 - bits)) & 63]);
  }
  return out;
}

std::optional<std::string> Base64UrlDecode(std::string_view text) {
  if (text.size() % 4 == 1) {
    return std::nullopt;
  }
  std::string out;
  out.reserve(text.size() * 3 / 4);
  uint32_t buffer = 0;
  int bits = 0;
  for (char character : text) {
    const int value = AlphabetIndex(kBase64UrlAlphabet, 64, character);
    if (value < 0) {
      return std::nullopt;
    }
    buffer = (buffer << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>(buffer >> bits));
      buffer &= (1u << bits) - 1;
    }
  }
  if (buffer != 0) {
    return std::nullopt;
  }
  return out;
}

std::optional<Key> KeyFromBytes(std::string_view bytes) {
  if (bytes.size() != kKeySize) {
    return std::nullopt;
  }
  Key key;
  memcpy(key.data(), bytes.data(), kKeySize);
  return key;
}

std::string_view KeyAsBytes(const Key& key) {
  return std::string_view(reinterpret_cast<const char*>(key.data()),
                          key.size());
}

Key RandomKey() {
  Key key;
  CHECK(RAND_bytes(key.data(), key.size()));
  return key;
}

Key Blake3(std::string_view data) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, data.data(), data.size());
  Key out;
  blake3_hasher_finalize(&hasher, out.data(), out.size());
  return out;
}

std::string SharedSecretChannelId(const Key& secret) {
  return Base64UrlEncode(KeyAsBytes(Blake3(KeyAsBytes(secret))));
}

std::string HpkeChannelId(const Key& recipient_public_key) {
  std::string input(kHpkeChannelDomain, sizeof(kHpkeChannelDomain));
  input.append(KeyAsBytes(recipient_public_key));
  return Base64UrlEncode(KeyAsBytes(Blake3(input)));
}

std::optional<std::string> OpenSecretBox(std::string_view message,
                                         const Key& key) {
  if (message.size() < kSecretBoxNonceSize + kSecretBoxTagSize) {
    return std::nullopt;
  }
  const std::string_view nonce = message.substr(0, kSecretBoxNonceSize);
  const std::string_view box = message.substr(kSecretBoxNonceSize);
  // NaCl's API wants 16 zero bytes before the tag and returns 32 zero bytes
  // before the plaintext.
  std::vector<uint8_t> padded(crypto_secretbox_BOXZEROBYTES + box.size(), 0);
  memcpy(padded.data() + crypto_secretbox_BOXZEROBYTES, box.data(),
         box.size());
  std::vector<uint8_t> plain(padded.size(), 0);
  if (crypto_secretbox_open(plain.data(), padded.data(), padded.size(),
                            Bytes(nonce), key.data()) != 0) {
    return std::nullopt;
  }
  std::string out(
      reinterpret_cast<const char*>(plain.data()) + crypto_secretbox_ZEROBYTES,
      plain.size() - crypto_secretbox_ZEROBYTES);
  OPENSSL_cleanse(plain.data(), plain.size());
  return out;
}

HpkeKeyPair GenerateHpkeKeyPair() {
  bssl::ScopedEVP_HPKE_KEY key;
  CHECK(EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256()));
  HpkeKeyPair pair;
  size_t length = 0;
  CHECK(EVP_HPKE_KEY_private_key(key.get(), pair.private_key.data(), &length,
                                 pair.private_key.size()));
  CHECK_EQ(length, kKeySize);
  CHECK(EVP_HPKE_KEY_public_key(key.get(), pair.public_key.data(), &length,
                                pair.public_key.size()));
  CHECK_EQ(length, kKeySize);
  return pair;
}

std::optional<Key> HpkePublicKeyFromPrivate(const Key& private_key) {
  bssl::ScopedEVP_HPKE_KEY key;
  if (!EVP_HPKE_KEY_init(key.get(), EVP_hpke_x25519_hkdf_sha256(),
                         private_key.data(), private_key.size())) {
    return std::nullopt;
  }
  Key public_key;
  size_t length = 0;
  if (!EVP_HPKE_KEY_public_key(key.get(), public_key.data(), &length,
                               public_key.size()) ||
      length != kKeySize) {
    return std::nullopt;
  }
  return public_key;
}

std::optional<std::string> OpenHpkeApproval(std::string_view wire,
                                            const Key& recipient_private_key) {
  const std::string_view prefix(kHpkeWirePrefix, kHpkeWirePrefixSize);
  if (!wire.starts_with(prefix)) {
    return std::nullopt;
  }
  const std::string_view body = wire.substr(prefix.size());
  if (body.size() <= kHpkeEncappedKeySize) {
    return std::nullopt;
  }
  const std::string_view encapped_key = body.substr(0, kHpkeEncappedKeySize);
  const std::string_view ciphertext = body.substr(kHpkeEncappedKeySize);

  bssl::ScopedEVP_HPKE_KEY key;
  if (!EVP_HPKE_KEY_init(key.get(), EVP_hpke_x25519_hkdf_sha256(),
                         recipient_private_key.data(),
                         recipient_private_key.size())) {
    return std::nullopt;
  }
  bssl::ScopedEVP_HPKE_CTX context;
  if (!EVP_HPKE_CTX_setup_recipient(
          context.get(), key.get(), EVP_hpke_hkdf_sha256(),
          EVP_hpke_chacha20_poly1305(), Bytes(encapped_key),
          encapped_key.size(), reinterpret_cast<const uint8_t*>(kHpkeInfo),
          sizeof(kHpkeInfo) - 1)) {
    return std::nullopt;
  }
  std::string plain(ciphertext.size(), '\0');
  size_t length = 0;
  if (!EVP_HPKE_CTX_open(context.get(), reinterpret_cast<uint8_t*>(plain.data()),
                         &length, plain.size(), Bytes(ciphertext),
                         ciphertext.size(), nullptr, 0)) {
    return std::nullopt;
  }
  plain.resize(length);
  return plain;
}

Key Ed25519PublicKey(const Key& seed) {
  Key public_key;
  uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
  ED25519_keypair_from_seed(public_key.data(), private_key, seed.data());
  OPENSSL_cleanse(private_key, sizeof(private_key));
  return public_key;
}

Signature Ed25519Sign(const Key& seed, std::string_view message) {
  uint8_t public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t private_key[ED25519_PRIVATE_KEY_LEN];
  ED25519_keypair_from_seed(public_key, private_key, seed.data());
  Signature signature;
  CHECK(ED25519_sign(signature.data(), Bytes(message), message.size(),
                     private_key));
  OPENSSL_cleanse(private_key, sizeof(private_key));
  return signature;
}

bool Ed25519Verify(const Key& public_key,
                   std::string_view message,
                   std::string_view signature) {
  if (signature.size() != kSignatureSize) {
    return false;
  }
  return ED25519_verify(Bytes(message), message.size(), Bytes(signature),
                        public_key.data()) == 1;
}

}  // namespace pubky_session

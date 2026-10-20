// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_CRYPTO_H_
#define COMPONENTS_PUBKY_SESSION_CORE_CRYPTO_H_

#include <stdint.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>

// Cryptographic and encoding primitives for Pubky grant sign-in. This file
// depends only on the C++ standard library, BoringSSL, BLAKE3 and TweetNaCl,
// so its behavior can be checked against the Pubky SDK outside Chromium.
namespace pubky_session {

inline constexpr size_t kKeySize = 32;
inline constexpr size_t kSignatureSize = 64;

// A 32-byte key: an Ed25519 public key or seed, an X25519 key, or a secret.
using Key = std::array<uint8_t, kKeySize>;
using Signature = std::array<uint8_t, kSignatureSize>;

// z-base-32, the 52-character text form of a Pubky public key.
std::string EncodeZ32(const Key& key);
std::optional<Key> DecodeZ32(std::string_view text);

// Unpadded base64url. Decoding rejects padding, other alphabets and
// non-zero trailing bits, as the SDK's decoder does.
std::string Base64UrlEncode(std::string_view bytes);
std::optional<std::string> Base64UrlDecode(std::string_view text);

// Converts between a byte string and a key, if the size is right.
std::optional<Key> KeyFromBytes(std::string_view bytes);
std::string_view KeyAsBytes(const Key& key);

// 32 bytes from the operating system's random source.
Key RandomKey();

// BLAKE3 with a 32-byte output.
Key Blake3(std::string_view data);

// Relay channel IDs: BLAKE3 of the shared secret, or of a domain-separated
// HPKE public key so the relay cannot encrypt to the recipient, in unpadded
// base64url.
std::string SharedSecretChannelId(const Key& secret);
std::string HpkeChannelId(const Key& recipient_public_key);

// Opens a NaCl secretbox message as the SDK writes it: a 24-byte nonce, the
// 16-byte Poly1305 tag, then the XSalsa20 ciphertext. Returns nullopt if the
// message is too short or does not authenticate.
std::optional<std::string> OpenSecretBox(std::string_view message,
                                         const Key& key);

// For tests: seals `plaintext` the way the SDK's relay channel does, with a
// random nonce.
std::string SealSecretBoxForTesting(std::string_view plaintext,
                                    const Key& key);

// HPKE recipient keys (X25519-HKDF-SHA256).
struct HpkeKeyPair {
  Key private_key;
  Key public_key;
};
HpkeKeyPair GenerateHpkeKeyPair();
std::optional<Key> HpkePublicKeyFromPrivate(const Key& private_key);

// Opens a signed approval delivered over HPKE: the wire prefix
// "pubky-hpke-v1\0", the 32-byte encapsulated key, then the ChaCha20-Poly1305
// ciphertext, with info "pubky-grant-approval-hpke-v1" and no associated data.
std::optional<std::string> OpenHpkeApproval(std::string_view wire,
                                            const Key& recipient_private_key);

// Ed25519 from a 32-byte seed.
Key Ed25519PublicKey(const Key& seed);
Signature Ed25519Sign(const Key& seed, std::string_view message);
bool Ed25519Verify(const Key& public_key,
                   std::string_view message,
                   std::string_view signature);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_CRYPTO_H_

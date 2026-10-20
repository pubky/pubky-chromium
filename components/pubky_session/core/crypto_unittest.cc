// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/crypto.h"

#include <string>

#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

std::string Bytes(const Signature& signature) {
  return std::string(signature.begin(), signature.end());
}

TEST(PubkySessionCryptoTest, Z32MatchesSdkKeys) {
  EXPECT_EQ(EncodeZ32(test::UserPublicKey()),
            VectorString("keys.user_public_z32"));
  EXPECT_EQ(DecodeZ32(VectorString("keys.user_public_z32")),
            test::UserPublicKey());
  EXPECT_EQ(EncodeZ32(Ed25519PublicKey(test::UserSeed())),
            VectorString("keys.user_public_z32"));
  EXPECT_EQ(EncodeZ32(Ed25519PublicKey(test::ClientSeed())),
            VectorString("keys.client_public_z32"));
}

TEST(PubkySessionCryptoTest, Z32RejectsMalformedKeys) {
  const std::string key = VectorString("keys.user_public_z32");
  EXPECT_FALSE(DecodeZ32(key.substr(1)));
  EXPECT_FALSE(DecodeZ32(key + "y"));
  std::string bad_letter = key;
  bad_letter[0] = 'l';
  EXPECT_FALSE(DecodeZ32(bad_letter));
  std::string upper = key;
  upper[0] = 'Y';
  EXPECT_FALSE(DecodeZ32(upper));
}

TEST(PubkySessionCryptoTest, Blake3MatchesSdk) {
  const base::ListValue* cases = test::Vectors().FindList("blake3");
  ASSERT_TRUE(cases);
  ASSERT_FALSE(cases->empty());
  for (const base::Value& entry : *cases) {
    const base::DictValue& dict = entry.GetDict();
    std::string input;
    ASSERT_TRUE(base::HexStringToString(*dict.FindString("input_hex"), &input));
    EXPECT_EQ(Blake3(input), test::KeyFromHex(*dict.FindString("hash_hex")));
  }
}

TEST(PubkySessionCryptoTest, RelayChannelIdsMatchSdk) {
  EXPECT_EQ(SharedSecretChannelId(test::KeyFromBase64Url(
                VectorString("relay.shared_secret_b64url"))),
            VectorString("relay.shared_channel_id"));
  const Key hpke_public =
      test::KeyFromBase64Url(VectorString("relay.hpke_recipient_public_b64url"));
  EXPECT_EQ(HpkePublicKeyFromPrivate(test::HpkePrivateKey()), hpke_public);
  EXPECT_EQ(HpkeChannelId(hpke_public), VectorString("relay.hpke_channel_id"));
}

TEST(PubkySessionCryptoTest, SecretBoxOpensSdkMessage) {
  const Key secret =
      test::KeyFromBase64Url(VectorString("relay.shared_secret_b64url"));
  const std::string message = test::BareRelayMessage();
  EXPECT_EQ(OpenSecretBox(message, secret), VectorString("bare_grant.jws"));

  std::string tampered = message;
  tampered[30] ^= 1;
  EXPECT_FALSE(OpenSecretBox(tampered, secret));
  Key wrong = secret;
  wrong[0] ^= 1;
  EXPECT_FALSE(OpenSecretBox(message, wrong));
  EXPECT_FALSE(OpenSecretBox(message.substr(0, 39), secret));
}

TEST(PubkySessionCryptoTest, HpkeOpensSdkApproval) {
  const std::string wire = test::SignedRelayMessage();
  EXPECT_EQ(OpenHpkeApproval(wire, test::HpkePrivateKey()),
            VectorString("signed_approval.approval_jws"));

  std::string tampered = wire;
  tampered.back() ^= 1;
  EXPECT_FALSE(OpenHpkeApproval(tampered, test::HpkePrivateKey()));
  EXPECT_FALSE(OpenHpkeApproval(wire.substr(1), test::HpkePrivateKey()));
  EXPECT_FALSE(OpenHpkeApproval(wire, GenerateHpkeKeyPair().private_key));
}

TEST(PubkySessionCryptoTest, GeneratedHpkeKeysAreConsistent) {
  const HpkeKeyPair pair = GenerateHpkeKeyPair();
  EXPECT_EQ(HpkePublicKeyFromPrivate(pair.private_key), pair.public_key);
  EXPECT_NE(GenerateHpkeKeyPair().public_key, pair.public_key);
}

TEST(PubkySessionCryptoTest, Ed25519SignsAndVerifies) {
  const Key seed = test::ClientSeed();
  const std::string signature = Bytes(Ed25519Sign(seed, "message"));
  EXPECT_TRUE(Ed25519Verify(Ed25519PublicKey(seed), "message", signature));
  EXPECT_FALSE(Ed25519Verify(Ed25519PublicKey(seed), "messagE", signature));
  EXPECT_FALSE(
      Ed25519Verify(Ed25519PublicKey(test::UserSeed()), "message", signature));
  EXPECT_FALSE(Ed25519Verify(Ed25519PublicKey(seed), "message",
                             signature.substr(1)));
}

TEST(PubkySessionCryptoTest, Base64Url) {
  EXPECT_EQ(Base64UrlEncode(""), "");
  EXPECT_EQ(Base64UrlEncode("\xfb\xff"), "-_8");
  EXPECT_EQ(Base64UrlDecode("-_8"), "\xfb\xff");
  EXPECT_EQ(Base64UrlDecode(Base64UrlEncode("hello world!?")), "hello world!?");
  EXPECT_FALSE(Base64UrlDecode("aGk="));
  EXPECT_FALSE(Base64UrlDecode("aGl"));
  EXPECT_FALSE(Base64UrlDecode("a+b/"));
  EXPECT_FALSE(Base64UrlDecode("a"));
}

TEST(PubkySessionCryptoTest, RandomKeysDiffer) {
  EXPECT_NE(RandomKey(), RandomKey());
}

}  // namespace
}  // namespace pubky_session

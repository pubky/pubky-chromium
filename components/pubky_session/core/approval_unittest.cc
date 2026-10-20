// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/approval.h"

#include <string>

#include "base/strings/string_number_conversions.h"
#include "components/pubky_session/core/jws.h"
#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

constexpr char kGrantId[] = "AAAAAAAAAAAAAAAAAAAAAA";

// A grant JWS for the test client, claiming `issuer` but signed by `signer`.
std::string GrantJws(const Key& signer,
                     const Key& issuer,
                     std::string_view caps_json,
                     uint64_t issued_at = 1760000000,
                     uint64_t expires_at = 1830000000) {
  const std::string payload =
      std::string("{\"caps\":") + std::string(caps_json) +
      ",\"client_id\":\"pubky-browser\",\"cnf\":\"" +
      EncodeZ32(Ed25519PublicKey(test::ClientSeed())) + "\",\"exp\":" +
      base::NumberToString(expires_at) + ",\"iat\":" +
      base::NumberToString(issued_at) + ",\"iss\":\"" + EncodeZ32(issuer) +
      "\",\"jti\":\"" + kGrantId + "\"}";
  return SignJws(kGrantJwsType, payload, signer);
}

std::string ApprovalJws(const Key& signer,
                        std::string_view grant_jws,
                        std::string_view keys_json) {
  const std::string payload =
      std::string("{\"encryption_keys\":{\"keys\":") + std::string(keys_json) +
      ",\"version\":\"v1\"},\"grant\":\"" + std::string(grant_jws) +
      "\",\"version\":\"v1\"}";
  return SignJws(kApprovalJwsType, payload, signer);
}

TEST(PubkySessionApprovalTest, OpensSdkBareGrant) {
  base::expected<GrantApproval, ApprovalError> approval =
      OpenApproval(test::BareRequest(), test::BareRelayMessage(), std::nullopt);
  ASSERT_TRUE(approval.has_value());
  EXPECT_EQ(approval->grant_jws, VectorString("bare_grant.jws"));
  EXPECT_EQ(approval->claims.issuer, test::UserPublicKey());
  EXPECT_EQ(approval->claims.client_key, Ed25519PublicKey(test::ClientSeed()));
  EXPECT_EQ(approval->claims.client_id, kBrowserClientId);
  EXPECT_EQ(approval->claims.capabilities, *ParseCapabilities("/pub/:rw"));
  EXPECT_EQ(approval->claims.grant_id, kGrantId);
  EXPECT_EQ(approval->claims.issued_at, 1760000000u);
  EXPECT_EQ(approval->claims.expires_at, 1830000000u);
  EXPECT_TRUE(approval->encryption_keys.empty());
}

TEST(PubkySessionApprovalTest, OpensSdkSignedApprovalWithKeys) {
  base::expected<GrantApproval, ApprovalError> approval =
      OpenApproval(test::SignedRequest(), test::SignedRelayMessage(),
                   test::HpkePrivateKey());
  ASSERT_TRUE(approval.has_value());
  EXPECT_EQ(approval->grant_jws, VectorString("signed_approval.grant_jws"));
  ASSERT_EQ(approval->encryption_keys.size(), 1u);
  EXPECT_EQ(approval->encryption_keys[0].scope, "/priv/notes/");
}

TEST(PubkySessionApprovalTest, RejectsMessagesItCannotOpen) {
  SigninGrantRequest wrong_secret = test::BareRequest();
  wrong_secret.channel_key[0] ^= 1;
  EXPECT_EQ(OpenApproval(wrong_secret, test::BareRelayMessage(), std::nullopt)
                .error(),
            ApprovalError::kUndecryptable);
  EXPECT_EQ(OpenApproval(test::SignedRequest(), test::SignedRelayMessage(),
                         std::nullopt)
                .error(),
            ApprovalError::kUndecryptable);
  EXPECT_EQ(OpenApproval(test::SignedRequest(), test::SignedRelayMessage(),
                         GenerateHpkeKeyPair().private_key)
                .error(),
            ApprovalError::kUndecryptable);
}

TEST(PubkySessionApprovalTest, RejectsAnotherClient) {
  SigninGrantRequest other_key = test::BareRequest();
  other_key.client_public_key = Ed25519PublicKey(test::UserSeed());
  EXPECT_EQ(
      OpenApproval(other_key, test::BareRelayMessage(), std::nullopt).error(),
      ApprovalError::kWrongClient);
  SigninGrantRequest other_id = test::BareRequest();
  other_id.client_id = "another-app";
  EXPECT_EQ(
      OpenApproval(other_id, test::BareRelayMessage(), std::nullopt).error(),
      ApprovalError::kWrongClient);
}

TEST(PubkySessionApprovalTest, CapabilitiesMayNarrowButNotWiden) {
  SigninGrantRequest narrower = test::BareRequest();
  narrower.capabilities = *ParseCapabilities("/pub/app/:rw");
  EXPECT_EQ(
      OpenApproval(narrower, test::BareRelayMessage(), std::nullopt).error(),
      ApprovalError::kCapabilitiesExceeded);
  SigninGrantRequest read_only = test::BareRequest();
  read_only.capabilities = *ParseCapabilities("/pub/:r");
  EXPECT_EQ(
      OpenApproval(read_only, test::BareRelayMessage(), std::nullopt).error(),
      ApprovalError::kCapabilitiesExceeded);
  SigninGrantRequest broader = test::BareRequest();
  broader.capabilities = *ParseCapabilities("/:rw");
  EXPECT_TRUE(
      OpenApproval(broader, test::BareRelayMessage(), std::nullopt).has_value());
}

TEST(PubkySessionApprovalTest, RejectsForgedGrant) {
  const std::string forged = GrantJws(test::ClientSeed(),
                                      test::UserPublicKey(), R"(["/pub/:rw"])");
  EXPECT_EQ(ParseApproval(ApprovalFormat::kBareGrant, forged).error(),
            ApprovalError::kBadSignature);
}

TEST(PubkySessionApprovalTest, RejectsBadTimestamps) {
  base::expected<GrantApproval, ApprovalError> approval = ParseApproval(
      ApprovalFormat::kBareGrant,
      GrantJws(test::UserSeed(), test::UserPublicKey(), R"(["/pub/:rw"])",
               1760000000, 1760000000));
  ASSERT_TRUE(approval.has_value());
  EXPECT_EQ(CheckApprovalMatchesRequest(*approval, test::BareRequest()),
            ApprovalError::kInvalidTimestamps);
}

TEST(PubkySessionApprovalTest, RejectsSignedApprovalFromAnotherKey) {
  const std::string grant = GrantJws(test::UserSeed(), test::UserPublicKey(),
                                     R"(["/pub/notes/:rw"])");
  EXPECT_TRUE(ParseApproval(ApprovalFormat::kSignedApprovalV1,
                            ApprovalJws(test::UserSeed(), grant, "[]"))
                  .has_value());
  EXPECT_EQ(ParseApproval(ApprovalFormat::kSignedApprovalV1,
                          ApprovalJws(test::ClientSeed(), grant, "[]"))
                .error(),
            ApprovalError::kBadSignature);
}

TEST(PubkySessionApprovalTest, KeysMustMatchTheGrant) {
  const std::string grant =
      GrantJws(test::UserSeed(), test::UserPublicKey(),
               R"(["/pub/notes/:rw","/priv/notes/:rwe"])");
  const std::string secret = Base64UrlEncode(std::string(32, 'k'));
  EXPECT_EQ(ParseApproval(ApprovalFormat::kSignedApprovalV1,
                          ApprovalJws(test::UserSeed(), grant, "[]"))
                .error(),
            ApprovalError::kEncryptionKeysMismatch);
  EXPECT_EQ(
      ParseApproval(ApprovalFormat::kSignedApprovalV1,
                    ApprovalJws(test::UserSeed(), grant,
                                R"([{"scope":"/priv/other/","secret":")" +
                                    secret + "\"}]"))
          .error(),
      ApprovalError::kEncryptionKeysMismatch);
  EXPECT_TRUE(
      ParseApproval(ApprovalFormat::kSignedApprovalV1,
                    ApprovalJws(test::UserSeed(), grant,
                                R"([{"scope":"/priv/notes/","secret":")" +
                                    secret + "\"}]"))
          .has_value());
}

TEST(PubkySessionApprovalTest, RejectsMalformedApprovals) {
  EXPECT_EQ(ParseApproval(ApprovalFormat::kBareGrant, "not a jws").error(),
            ApprovalError::kMalformed);
  // A bare grant where a signed approval was requested.
  EXPECT_EQ(ParseApproval(ApprovalFormat::kSignedApprovalV1,
                          VectorString("bare_grant.jws"))
                .error(),
            ApprovalError::kMalformed);
  // A grant missing its capabilities.
  const std::string no_caps =
      SignJws(kGrantJwsType, R"({"client_id":"pubky-browser"})",
              test::UserSeed());
  EXPECT_EQ(ParseApproval(ApprovalFormat::kBareGrant, no_caps).error(),
            ApprovalError::kMalformed);
}

}  // namespace
}  // namespace pubky_session

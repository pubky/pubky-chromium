// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/grant_session.h"

#include "base/json/json_writer.h"
#include "base/time/time.h"
#include "components/pubky_session/core/jws.h"
#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

constexpr char kGrantId[] = "AAAAAAAAAAAAAAAAAAAAAA";

TEST(PubkySessionGrantSessionTest, PopProofMatchesSdk) {
  const std::optional<int> iat = test::Vectors().FindIntByDottedPath("pop.iat");
  ASSERT_TRUE(iat);
  EXPECT_EQ(CreatePopProofForTesting(test::ClientSeed(),
                                     test::HomeserverPublicKey(), kGrantId,
                                     base::Time::FromTimeT(*iat),
                                     VectorString("pop.nonce")),
            VectorString("pop.jws"));
}

TEST(PubkySessionGrantSessionTest, PopProofsUseFreshNonces) {
  const base::Time now = base::Time::FromTimeT(1760000000);
  const std::string first = CreatePopProof(
      test::ClientSeed(), test::HomeserverPublicKey(), kGrantId, now);
  const std::string second = CreatePopProof(
      test::ClientSeed(), test::HomeserverPublicKey(), kGrantId, now);
  EXPECT_NE(first, second);

  std::optional<Jws> jws = ParseJws(first);
  ASSERT_TRUE(jws);
  EXPECT_EQ(jws->type, kPopJwsType);
  EXPECT_TRUE(VerifyJws(*jws, Ed25519PublicKey(test::ClientSeed())));
  EXPECT_EQ(*jws->payload.FindString("aud"),
            VectorString("keys.homeserver_public_z32"));
  EXPECT_EQ(*jws->payload.FindString("gid"), kGrantId);
  EXPECT_EQ(jws->payload.FindString("nonce")->size(), 22u);
  EXPECT_EQ(FindUnsigned(jws->payload, "iat"), 1760000000u);
}

TEST(PubkySessionGrantSessionTest, RequestBodyMatchesSdk) {
  EXPECT_EQ(CreateGrantSessionRequestBody(VectorString("bare_grant.jws"),
                                          VectorString("pop.jws")),
            VectorString("pop.exchange_body"));
}

TEST(PubkySessionGrantSessionTest, ParsesSdkSessionResponse) {
  const base::DictValue* response =
      test::Vectors().FindDict("session_response");
  ASSERT_TRUE(response);
  std::optional<std::string> json = base::WriteJson(*response);
  ASSERT_TRUE(json);

  std::optional<GrantSession> session = ParseGrantSessionResponse(*json);
  ASSERT_TRUE(session);
  EXPECT_EQ(session->token, "bearer-token-for-tests");
  EXPECT_EQ(session->homeserver, test::HomeserverPublicKey());
  EXPECT_EQ(session->user, test::UserPublicKey());
  EXPECT_EQ(session->client_id, kBrowserClientId);
  EXPECT_EQ(session->capabilities, *ParseCapabilities("/pub/:rw"));
  EXPECT_EQ(session->grant_id, kGrantId);
  EXPECT_EQ(session->token_expires_at, 1760003600u);
  EXPECT_EQ(session->grant_expires_at, 1830000000u);
  EXPECT_EQ(session->created_at, 1760000000u);
}

TEST(PubkySessionGrantSessionTest, RejectsIncompleteResponses) {
  EXPECT_FALSE(ParseGrantSessionResponse("not json"));
  EXPECT_FALSE(ParseGrantSessionResponse(R"({"token":"t"})"));
  EXPECT_FALSE(ParseGrantSessionResponse(R"({"token":"","session":{}})"));
  EXPECT_FALSE(ParseGrantSessionResponse(R"({"token":"t","session":{}})"));
}

}  // namespace
}  // namespace pubky_session

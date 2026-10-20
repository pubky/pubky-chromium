// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/session_store.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

StoredSession Example() {
  StoredSession session;
  session.client_seed.fill(1);
  session.grant_jws = "header.payload.signature";
  session.user.fill(2);
  session.homeserver.fill(3);
  session.grant_id = "AAAAAAAAAAAAAAAAAAAAAA";
  session.capabilities = *ParseCapabilities("/pub/:rw,/priv/notes/:rwe");
  session.bearer = "bearer";
  session.token_expires_at = 4102444800;  // Past 2038.
  session.grant_expires_at = 4102448400;
  Key secret;
  secret.fill(4);
  session.encryption_keys.push_back({"/priv/notes/", secret});
  ScopeGrant scope_grant;
  scope_grant.grant_jws = "header.scope.signature";
  scope_grant.grant_id = "BBBBBBBBBBBBBBBBBBBBBB";
  scope_grant.capabilities = *ParseCapabilities("/priv/app/:rw");
  scope_grant.bearer = "scope-bearer";
  scope_grant.token_expires_at = 4102444801;
  scope_grant.grant_expires_at = 4102448401;
  session.scope_grants.push_back(scope_grant);
  return session;
}

TEST(PubkySessionStoreTest, RoundTrips) {
  const StoredSession session = Example();
  std::optional<StoredSession> parsed =
      ParseStoredSession(SerializeStoredSession(session));
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->client_seed, session.client_seed);
  EXPECT_EQ(parsed->grant_jws, session.grant_jws);
  EXPECT_EQ(parsed->user, session.user);
  EXPECT_EQ(parsed->homeserver, session.homeserver);
  EXPECT_EQ(parsed->grant_id, session.grant_id);
  EXPECT_EQ(parsed->capabilities, session.capabilities);
  EXPECT_EQ(parsed->bearer, session.bearer);
  EXPECT_EQ(parsed->token_expires_at, session.token_expires_at);
  EXPECT_EQ(parsed->grant_expires_at, session.grant_expires_at);
  ASSERT_EQ(parsed->encryption_keys.size(), 1u);
  EXPECT_EQ(parsed->encryption_keys[0].scope, "/priv/notes/");
  EXPECT_EQ(parsed->encryption_keys[0].secret,
            session.encryption_keys[0].secret);
  ASSERT_EQ(parsed->scope_grants.size(), 1u);
  const ScopeGrant& scope_grant = parsed->scope_grants[0];
  EXPECT_EQ(scope_grant.grant_jws, "header.scope.signature");
  EXPECT_EQ(scope_grant.grant_id, "BBBBBBBBBBBBBBBBBBBBBB");
  EXPECT_EQ(scope_grant.capabilities, *ParseCapabilities("/priv/app/:rw"));
  EXPECT_EQ(scope_grant.bearer, "scope-bearer");
  EXPECT_EQ(scope_grant.token_expires_at, 4102444801u);
  EXPECT_EQ(scope_grant.grant_expires_at, 4102448401u);
}

TEST(PubkySessionStoreTest, RejectsDamagedRecords) {
  EXPECT_FALSE(ParseStoredSession(""));
  EXPECT_FALSE(ParseStoredSession("{}"));
  EXPECT_FALSE(ParseStoredSession(R"({"version":2})"));
  std::string json = SerializeStoredSession(Example());
  json.replace(json.find("\"bearer\""), 8, "\"bearex\"");
  EXPECT_FALSE(ParseStoredSession(json));
  json = SerializeStoredSession(Example());
  json.replace(json.find("\"scope_grants\""), 14, "\"scope_grantx\"");
  EXPECT_FALSE(ParseStoredSession(json));
}

}  // namespace
}  // namespace pubky_session

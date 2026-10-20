// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/signin_link.h"

#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

TEST(PubkySessionSigninLinkTest, BareGrantLinkMatchesSdk) {
  EXPECT_EQ(BuildSigninGrantLink(test::BareRequest()),
            VectorString("links.bare"));
}

TEST(PubkySessionSigninLinkTest, SignedApprovalLinkMatchesSdk) {
  EXPECT_EQ(BuildSigninGrantLink(test::SignedRequest()),
            VectorString("links.signed"));
}

TEST(PubkySessionSigninLinkTest, RelayChannelUrl) {
  EXPECT_EQ(RelayChannelUrl(test::BareRequest()),
            VectorString("relay.inbox") + "/" +
                VectorString("relay.shared_channel_id"));
  SigninGrantRequest trailing_slash = test::SignedRequest();
  trailing_slash.relay += "/";
  EXPECT_EQ(RelayChannelUrl(trailing_slash),
            VectorString("relay.inbox") + "/" +
                VectorString("relay.hpke_channel_id"));
}

TEST(PubkySessionSigninLinkTest, FormUrlEncode) {
  EXPECT_EQ(FormUrlEncode("/pub/:rw,a b"), "%2Fpub%2F%3Arw%2Ca+b");
  EXPECT_EQ(FormUrlEncode("az09*-._~"), "az09*-._%7E");
  EXPECT_EQ(FormUrlEncode("\xC3\xBC"), "%C3%BC");
}

}  // namespace
}  // namespace pubky_session

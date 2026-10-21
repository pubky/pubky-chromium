// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/jws.h"

#include "base/json/json_reader.h"
#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

TEST(PubkySessionJwsTest, ParsesAndVerifiesSdkGrant) {
  std::optional<Jws> jws = ParseJws(VectorString("bare_grant.jws"));
  ASSERT_TRUE(jws);
  EXPECT_EQ(jws->type, kGrantJwsType);
  EXPECT_EQ(*jws->payload.FindString("iss"),
            VectorString("keys.user_public_z32"));
  EXPECT_TRUE(VerifyJws(*jws, test::UserPublicKey()));
  EXPECT_FALSE(VerifyJws(*jws, Ed25519PublicKey(test::ClientSeed())));
}

TEST(PubkySessionJwsTest, RejectsTamperedPayload) {
  std::string compact = VectorString("bare_grant.jws");
  const size_t payload = compact.find('.') + 5;
  compact[payload] = compact[payload] == 'A' ? 'B' : 'A';
  std::optional<Jws> jws = ParseJws(compact);
  EXPECT_TRUE(!jws || !VerifyJws(*jws, test::UserPublicKey()));
}

TEST(PubkySessionJwsTest, RejectsMalformedCompactForms) {
  const std::string payload = Base64UrlEncode("{}");
  const std::string signature = Base64UrlEncode(std::string(64, 'x'));
  const auto compact = [&](std::string_view header) {
    return Base64UrlEncode(header) + "." + payload + "." + signature;
  };
  EXPECT_TRUE(ParseJws(compact(R"({"alg":"EdDSA","typ":"t"})")));
  EXPECT_FALSE(ParseJws(compact(R"({"alg":"none","typ":"t"})")));
  EXPECT_FALSE(ParseJws(compact(R"({"alg":"EdDSA"})")));
  EXPECT_FALSE(ParseJws(compact(R"({"alg":"EdDSA","typ":"t"})") + ".x"));
  EXPECT_FALSE(ParseJws(Base64UrlEncode(R"({"alg":"EdDSA","typ":"t"})") +
                        "." + payload + "." + Base64UrlEncode("short")));
  EXPECT_FALSE(ParseJws(Base64UrlEncode(R"({"alg":"EdDSA","typ":"t"})") +
                        "." + Base64UrlEncode("[]") + "." + signature));
  EXPECT_FALSE(ParseJws("no-dots"));
}

TEST(PubkySessionJwsTest, SignsAndParses) {
  const std::string compact =
      SignJws("pubky-test", R"({"a":1})", test::ClientSeed());
  std::optional<Jws> jws = ParseJws(compact);
  ASSERT_TRUE(jws);
  EXPECT_EQ(jws->type, "pubky-test");
  EXPECT_EQ(jws->payload.FindInt("a"), 1);
  EXPECT_TRUE(VerifyJws(*jws, Ed25519PublicKey(test::ClientSeed())));
}

TEST(PubkySessionJwsTest, FindUnsigned) {
  std::optional<base::DictValue> dict = base::JSONReader::ReadDict(
      R"({"small":7,"large":3000000000,"negative":-1,"fraction":1.5})",
      base::JSON_PARSE_RFC);
  ASSERT_TRUE(dict);
  EXPECT_EQ(FindUnsigned(*dict, "small"), 7u);
  EXPECT_EQ(FindUnsigned(*dict, "large"), 3000000000u);
  EXPECT_FALSE(FindUnsigned(*dict, "negative"));
  EXPECT_FALSE(FindUnsigned(*dict, "fraction"));
  EXPECT_FALSE(FindUnsigned(*dict, "missing"));
}

}  // namespace
}  // namespace pubky_session

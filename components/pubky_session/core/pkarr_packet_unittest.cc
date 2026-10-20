// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/pkarr_packet.h"

#include <string>

#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using test::VectorString;

std::string Payload(std::string_view name) {
  return test::DecodeBase64(VectorString(std::string("pkarr.") +
                                         std::string(name) + "_b64"));
}

TEST(PubkySessionPkarrPacketTest, ReadsTheHomeserverFromSdkPackets) {
  const Key user = test::UserPublicKey();
  std::optional<SignedPacket> only =
      VerifyRelayPayload(user, Payload("homeserver_only"));
  ASSERT_TRUE(only);
  EXPECT_EQ(only->timestamp, 1760000000000000u);
  EXPECT_EQ(FindHomeserver(user, only->dns_packet),
            test::HomeserverPublicKey());

  std::optional<SignedPacket> mixed =
      VerifyRelayPayload(user, Payload("mixed"));
  ASSERT_TRUE(mixed);
  EXPECT_EQ(FindHomeserver(user, mixed->dns_packet),
            test::HomeserverPublicKey());

  std::optional<SignedPacket> none =
      VerifyRelayPayload(user, Payload("no_pubky"));
  ASSERT_TRUE(none);
  EXPECT_FALSE(FindHomeserver(user, none->dns_packet));
}

TEST(PubkySessionPkarrPacketTest, RejectsForgedOrDamagedPayloads) {
  const Key user = test::UserPublicKey();
  const std::string payload = Payload("homeserver_only");
  EXPECT_FALSE(
      VerifyRelayPayload(Ed25519PublicKey(test::ClientSeed()), payload));
  std::string tampered = payload;
  tampered.back() ^= 1;
  EXPECT_FALSE(VerifyRelayPayload(user, tampered));
  EXPECT_FALSE(VerifyRelayPayload(user, payload.substr(0, 71)));
  EXPECT_FALSE(
      VerifyRelayPayload(user, payload + std::string(kMaxRelayPayloadSize, 'x')));
}

TEST(PubkySessionPkarrPacketTest, IgnoresOtherUsersAndMalformedPackets) {
  const Key user = test::UserPublicKey();
  std::optional<SignedPacket> only =
      VerifyRelayPayload(user, Payload("homeserver_only"));
  ASSERT_TRUE(only);
  EXPECT_FALSE(
      FindHomeserver(Ed25519PublicKey(test::ClientSeed()), only->dns_packet));
  EXPECT_FALSE(FindHomeserver(user, ""));
  EXPECT_FALSE(FindHomeserver(
      user, std::string("\x00\x00\x84\x00\x00\x00\x00\x05\x00\x00\x00\x00", 12)));
  // An answer whose name is a pointer to itself.
  EXPECT_FALSE(FindHomeserver(
      user,
      std::string("\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\xc0\x0c",
                  14)));
}

TEST(PubkySessionPkarrPacketTest, TestBuildersRoundTrip) {
  const Key user = Ed25519PublicKey(test::UserSeed());
  const Key homeserver = test::HomeserverPublicKey();
  std::optional<SignedPacket> packet = VerifyRelayPayload(
      user, SignRelayPayloadForTesting(
                test::UserSeed(), 42,
                BuildPubkyRecordPacketForTesting(user, homeserver)));
  ASSERT_TRUE(packet);
  EXPECT_EQ(packet->timestamp, 42u);
  EXPECT_EQ(FindHomeserver(user, packet->dns_packet), homeserver);
}

}  // namespace
}  // namespace pubky_session

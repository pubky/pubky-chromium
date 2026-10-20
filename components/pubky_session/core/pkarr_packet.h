// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_PKARR_PACKET_H_
#define COMPONENTS_PUBKY_SESSION_CORE_PKARR_PACKET_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>

#include "components/pubky_session/core/crypto.h"

// Signed PKARR packets as pkarr relays serve them, and the `_pubky` record
// that names a user's homeserver. Uses only the standard library and
// //components/pubky_session/core:crypto.
namespace pubky_session {

// pkarr's SignedPacket::MAX_BYTES, minus the 32-byte public key that relays
// leave out.
inline constexpr size_t kMaxRelayPayloadSize = 1072;

struct SignedPacket {
  // Microseconds since the Unix epoch, chosen by the key holder.
  uint64_t timestamp = 0;
  // The encoded DNS packet.
  std::string dns_packet;
};

// Verifies a relay response body for `public_key`: a 64-byte Ed25519
// signature, an 8-byte big-endian timestamp, then the DNS packet. The
// signature covers the BEP 44 form "3:seqi<timestamp>e1:v<length>:<packet>".
std::optional<SignedPacket> VerifyRelayPayload(const Key& public_key,
                                               std::string_view payload);

// The homeserver key named by the first SVCB or HTTPS answer whose owner is
// `_pubky.<user>`, as the SDK reads it. Returns nullopt when there is no such
// record, when its target is not a single public-key label, or when the
// packet is malformed.
std::optional<Key> FindHomeserver(const Key& user, std::string_view dns_packet);

// For tests: a DNS packet with one `_pubky` HTTPS AliasMode record pointing
// at `homeserver`, and a relay payload signed with `seed`.
std::string BuildPubkyRecordPacketForTesting(const Key& user,
                                             const Key& homeserver);
std::string SignRelayPayloadForTesting(const Key& seed,
                                       uint64_t timestamp,
                                       std::string_view dns_packet);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_PKARR_PACKET_H_

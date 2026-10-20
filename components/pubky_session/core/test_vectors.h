// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_TEST_VECTORS_H_
#define COMPONENTS_PUBKY_SESSION_CORE_TEST_VECTORS_H_

#include <string>
#include <string_view>

#include "base/values.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/core/signin_link.h"

// Fixtures generated from the Pubky Rust SDK, in test_data/sdk_vectors.json.
namespace pubky_session::test {

const base::DictValue& Vectors();

// A string at a dotted path, for example "relay.shared_channel_id".
const std::string& VectorString(std::string_view path);

Key KeyFromHex(std::string_view hex);
Key KeyFromBase64Url(std::string_view text);
std::string DecodeBase64(std::string_view text);

Key UserSeed();
Key UserPublicKey();
Key ClientSeed();
Key HomeserverPublicKey();
Key HpkePrivateKey();

// The requests the SDK vectors were generated for.
SigninGrantRequest BareRequest();
SigninGrantRequest SignedRequest();

// The relay messages carrying the bare grant and the signed approval.
std::string BareRelayMessage();
std::string SignedRelayMessage();

}  // namespace pubky_session::test

#endif  // COMPONENTS_PUBKY_SESSION_CORE_TEST_VECTORS_H_

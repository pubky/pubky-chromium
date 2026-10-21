// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_SIGNIN_LINK_H_
#define COMPONENTS_PUBKY_SESSION_CORE_SIGNIN_LINK_H_

#include <string>
#include <string_view>
#include <vector>

#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"

namespace pubky_session {

// The client ID the browser's grant is issued to.
inline constexpr char kBrowserClientId[] = "pubky-browser";
inline constexpr char kDefaultRelayInbox[] =
    "https://httprelay.pubky.app/inbox";

enum class ApprovalFormat {
  // A grant JWS, encrypted to a shared secret with XSalsa20-Poly1305.
  kBareGrant,
  // A signed approval with optional encryption keys, encrypted with HPKE.
  // Required when any capability asks for encryption keys.
  kSignedApprovalV1,
};

// A pending `pubkyauth://signin_grant` request.
struct SigninGrantRequest {
  std::vector<Capability> capabilities;
  // HTTP relay inbox base URL, without the channel ID.
  std::string relay;
  std::string client_id = kBrowserClientId;
  // The public half of the browser's proof-of-possession key, bound by the
  // grant's `cnf` claim.
  Key client_public_key{};
  ApprovalFormat format = ApprovalFormat::kBareGrant;
  // The shared secret for kBareGrant, or the HPKE recipient public key for
  // kSignedApprovalV1.
  Key channel_key{};
};

// The link shown as a QR code or opened in a signer. Query parameters, in
// order: caps, relay, cid, cpk, then af=v1 and epk, or secret.
std::string BuildSigninGrantLink(const SigninGrantRequest& request);

// The relay channel ID and the URL the browser long-polls for the approval.
std::string RelayChannelId(const SigninGrantRequest& request);
std::string RelayChannelUrl(const SigninGrantRequest& request);

// application/x-www-form-urlencoded byte serialization, as the SDK's URL
// library writes query values.
std::string FormUrlEncode(std::string_view value);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_SIGNIN_LINK_H_

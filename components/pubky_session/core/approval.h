// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_APPROVAL_H_
#define COMPONENTS_PUBKY_SESSION_CORE_APPROVAL_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/types/expected.h"
#include "base/values.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/core/signin_link.h"

namespace pubky_session {

// The claims of a grant JWS (typ "pubky-grant"), signed by the user's key.
struct GrantClaims {
  GrantClaims();
  GrantClaims(const GrantClaims&);
  GrantClaims& operator=(const GrantClaims&);
  ~GrantClaims();

  // `iss`: the user's public key.
  Key issuer{};
  std::string client_id;
  std::vector<Capability> capabilities;
  // `cnf`: the client key that must prove possession at the homeserver.
  Key client_key{};
  // `jti`: 1 to 22 base64url characters.
  std::string grant_id;
  uint64_t issued_at = 0;
  uint64_t expires_at = 0;
};

std::optional<GrantClaims> ParseGrantClaims(const base::DictValue& payload);

// A scoped encryption key from a signed approval. Keys are permanent: the
// browser must keep them only as long as the site that asked for them.
struct EncryptionKey {
  std::string scope;
  Key secret{};
};

struct GrantApproval {
  GrantApproval();
  GrantApproval(GrantApproval&&);
  GrantApproval& operator=(GrantApproval&&);
  ~GrantApproval();

  // The grant JWS to present to the homeserver.
  std::string grant_jws;
  GrantClaims claims;
  // Empty for bare grants and for signed approvals without "e".
  std::vector<EncryptionKey> encryption_keys;
};

enum class ApprovalError {
  // The message did not decrypt with the request's key.
  kUndecryptable,
  // The message decrypted but is not a well-formed approval.
  kMalformed,
  // A signature does not verify with the grant's issuer.
  kBadSignature,
  // `cnf` or `client_id` does not match the request.
  kWrongClient,
  // `iat` is not before `exp`.
  kInvalidTimestamps,
  // The signer approved more than the request asked for.
  kCapabilitiesExceeded,
  // The key bundle does not match the grant's "e" scopes.
  kEncryptionKeysMismatch,
};

// Parses a decrypted approval and verifies its signatures: a grant JWS for
// kBareGrant, or a signed approval whose outer signature binds the grant and
// the key bundle for kSignedApprovalV1.
base::expected<GrantApproval, ApprovalError> ParseApproval(
    ApprovalFormat format,
    std::string_view plaintext);

// Checks a parsed approval against the pending request: the client binding,
// the timestamps and that every approved action was requested.
std::optional<ApprovalError> CheckApprovalMatchesRequest(
    const GrantApproval& approval,
    const SigninGrantRequest& request);

// Opens a relay message for `request` and checks it as the SDK does: the
// signatures, the client binding, the timestamps and that every approved
// action was requested. Signers may narrow the request. For
// kSignedApprovalV1, `hpke_private_key` is the private half of
// `request.channel_key`; it is ignored for bare grants. Expiry against the
// clock is left to the homeserver.
base::expected<GrantApproval, ApprovalError> OpenApproval(
    const SigninGrantRequest& request,
    std::string_view relay_message,
    const std::optional<Key>& hpke_private_key);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_APPROVAL_H_

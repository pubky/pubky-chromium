// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/approval.h"

#include <set>
#include <utility>

#include "base/types/expected_macros.h"
#include "components/pubky_session/core/jws.h"

namespace pubky_session {

namespace {

constexpr size_t kMaxGrantIdLength = 22;
constexpr char kApprovalVersion[] = "v1";

bool IsGrantId(std::string_view text) {
  if (text.empty() || text.size() > kMaxGrantIdLength) {
    return false;
  }
  for (char c : text) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_';
    if (!ok) {
      return false;
    }
  }
  return true;
}

// The "encryption_keys" bundle: {"version":"v1","keys":[{"scope","secret"}]}.
std::optional<std::vector<EncryptionKey>> ParseKeyBundle(
    const base::DictValue& bundle) {
  const std::string* version = bundle.FindString("version");
  const base::ListValue* keys = bundle.FindList("keys");
  if (!version || *version != kApprovalVersion || !keys) {
    return std::nullopt;
  }
  std::vector<EncryptionKey> out;
  for (const base::Value& entry : *keys) {
    const base::DictValue* dict = entry.GetIfDict();
    if (!dict) {
      return std::nullopt;
    }
    const std::string* scope = dict->FindString("scope");
    const std::string* secret = dict->FindString("secret");
    if (!scope || !secret || !IsCanonicalStoragePath(*scope)) {
      return std::nullopt;
    }
    std::optional<std::string> raw = Base64UrlDecode(*secret);
    std::optional<Key> key = raw ? KeyFromBytes(*raw) : std::nullopt;
    if (!key) {
      return std::nullopt;
    }
    out.push_back({*scope, *key});
  }
  return out;
}

// Keys must cover exactly the scopes whose grant capability has "e".
bool KeysMatchGrant(const std::vector<EncryptionKey>& keys,
                    const GrantClaims& claims) {
  std::set<std::string> expected;
  for (const Capability& capability : claims.capabilities) {
    if (capability.encryption_keys) {
      expected.insert(capability.scope);
    }
  }
  std::set<std::string> actual;
  for (const EncryptionKey& key : keys) {
    if (!actual.insert(key.scope).second) {
      return false;
    }
  }
  return actual == expected;
}

base::expected<GrantApproval, ApprovalError> ParseBareGrant(
    std::string_view grant_jws) {
  std::optional<Jws> jws = ParseJws(grant_jws);
  if (!jws || jws->type != kGrantJwsType) {
    return base::unexpected(ApprovalError::kMalformed);
  }
  std::optional<GrantClaims> claims = ParseGrantClaims(jws->payload);
  if (!claims) {
    return base::unexpected(ApprovalError::kMalformed);
  }
  if (!VerifyJws(*jws, claims->issuer)) {
    return base::unexpected(ApprovalError::kBadSignature);
  }
  GrantApproval approval;
  approval.grant_jws = std::string(grant_jws);
  approval.claims = std::move(*claims);
  return approval;
}

base::expected<GrantApproval, ApprovalError> ParseSignedApproval(
    std::string_view approval_jws) {
  std::optional<Jws> outer = ParseJws(approval_jws);
  if (!outer || outer->type != kApprovalJwsType) {
    return base::unexpected(ApprovalError::kMalformed);
  }
  const std::string* version = outer->payload.FindString("version");
  const std::string* grant = outer->payload.FindString("grant");
  const base::DictValue* bundle = outer->payload.FindDict("encryption_keys");
  if (!version || *version != kApprovalVersion || !grant || !bundle) {
    return base::unexpected(ApprovalError::kMalformed);
  }
  // The inner grant names the issuer; the outer signature binds the issuer,
  // the exact grant and the keys, so check it before reading the keys.
  ASSIGN_OR_RETURN(GrantApproval approval, ParseBareGrant(*grant));
  if (!VerifyJws(*outer, approval.claims.issuer)) {
    return base::unexpected(ApprovalError::kBadSignature);
  }
  std::optional<std::vector<EncryptionKey>> keys = ParseKeyBundle(*bundle);
  if (!keys) {
    return base::unexpected(ApprovalError::kMalformed);
  }
  if (!KeysMatchGrant(*keys, approval.claims)) {
    return base::unexpected(ApprovalError::kEncryptionKeysMismatch);
  }
  approval.encryption_keys = std::move(*keys);
  return approval;
}

}  // namespace

GrantClaims::GrantClaims() = default;
GrantClaims::GrantClaims(const GrantClaims&) = default;
GrantClaims& GrantClaims::operator=(const GrantClaims&) = default;
GrantClaims::~GrantClaims() = default;

GrantApproval::GrantApproval() = default;
GrantApproval::GrantApproval(GrantApproval&&) = default;
GrantApproval& GrantApproval::operator=(GrantApproval&&) = default;
GrantApproval::~GrantApproval() = default;

std::optional<GrantClaims> ParseGrantClaims(const base::DictValue& payload) {
  GrantClaims claims;
  std::optional<Key> issuer = FindPublicKey(payload, "iss");
  std::optional<Key> client_key = FindPublicKey(payload, "cnf");
  const std::string* client_id = payload.FindString("client_id");
  const std::string* grant_id = payload.FindString("jti");
  const base::ListValue* capabilities = payload.FindList("caps");
  std::optional<uint64_t> issued_at = FindUnsigned(payload, "iat");
  std::optional<uint64_t> expires_at = FindUnsigned(payload, "exp");
  if (!issuer || !client_key || !client_id || client_id->empty() ||
      !grant_id || !IsGrantId(*grant_id) || !capabilities || !issued_at ||
      !expires_at) {
    return std::nullopt;
  }
  for (const base::Value& entry : *capabilities) {
    const std::string* text = entry.GetIfString();
    std::optional<Capability> capability =
        text ? ParseCapability(*text) : std::nullopt;
    if (!capability) {
      return std::nullopt;
    }
    claims.capabilities.push_back(std::move(*capability));
  }
  claims.issuer = *issuer;
  claims.client_key = *client_key;
  claims.client_id = *client_id;
  claims.grant_id = *grant_id;
  claims.issued_at = *issued_at;
  claims.expires_at = *expires_at;
  return claims;
}

base::expected<GrantApproval, ApprovalError> ParseApproval(
    ApprovalFormat format,
    std::string_view plaintext) {
  return format == ApprovalFormat::kSignedApprovalV1
             ? ParseSignedApproval(plaintext)
             : ParseBareGrant(plaintext);
}

std::optional<ApprovalError> CheckApprovalMatchesRequest(
    const GrantApproval& approval,
    const SigninGrantRequest& request) {
  const GrantClaims& claims = approval.claims;
  if (claims.client_key != request.client_public_key ||
      claims.client_id != request.client_id) {
    return ApprovalError::kWrongClient;
  }
  // The homeserver judges expiry with its own clock; only the order of the
  // timestamps is checked here.
  if (claims.issued_at >= claims.expires_at) {
    return ApprovalError::kInvalidTimestamps;
  }
  for (const Capability& approved : claims.capabilities) {
    if (!CapabilitiesCover(request.capabilities, approved)) {
      return ApprovalError::kCapabilitiesExceeded;
    }
  }
  return std::nullopt;
}

base::expected<GrantApproval, ApprovalError> OpenApproval(
    const SigninGrantRequest& request,
    std::string_view relay_message,
    const std::optional<Key>& hpke_private_key) {
  std::optional<std::string> plain;
  if (request.format == ApprovalFormat::kSignedApprovalV1) {
    if (hpke_private_key) {
      plain = OpenHpkeApproval(relay_message, *hpke_private_key);
    }
  } else {
    plain = OpenSecretBox(relay_message, request.channel_key);
  }
  if (!plain) {
    return base::unexpected(ApprovalError::kUndecryptable);
  }
  ASSIGN_OR_RETURN(GrantApproval approval,
                   ParseApproval(request.format, *plain));
  if (std::optional<ApprovalError> error =
          CheckApprovalMatchesRequest(approval, request)) {
    return base::unexpected(*error);
  }
  return approval;
}

}  // namespace pubky_session

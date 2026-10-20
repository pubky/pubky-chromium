// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_JWS_H_
#define COMPONENTS_PUBKY_SESSION_CORE_JWS_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>

#include "base/values.h"
#include "components/pubky_session/core/crypto.h"

// Compact EdDSA JSON Web Signatures, as pubky-common writes them: the header
// is {"alg":"EdDSA","typ":<type>} and the signature is Ed25519 over
// "<base64url header>.<base64url payload>".
namespace pubky_session {

inline constexpr char kGrantJwsType[] = "pubky-grant";
inline constexpr char kApprovalJwsType[] = "pubky-grant-approval";
inline constexpr char kPopJwsType[] = "pubky-pop";

struct Jws {
  Jws();
  Jws(Jws&&);
  Jws& operator=(Jws&&);
  ~Jws();

  std::string type;
  base::DictValue payload;
  // "<base64url header>.<base64url payload>", the signed bytes.
  std::string signing_input;
  // The raw 64-byte Ed25519 signature.
  std::string signature;
};

// Parses a compact JWS with alg EdDSA and a string typ. The payload must be a
// JSON object. Does not check the signature.
std::optional<Jws> ParseJws(std::string_view compact);

// Whether `jws` was signed by `signer`.
bool VerifyJws(const Jws& jws, const Key& signer);

// Signs `payload_json`, which must be a JSON object, with the Ed25519 key
// derived from `seed`.
std::string SignJws(std::string_view type,
                    std::string_view payload_json,
                    const Key& seed);

// Reads a non-negative integer that JSON may carry as an int or a double.
std::optional<uint64_t> FindUnsigned(const base::DictValue& dict,
                                     std::string_view key);

// Reads a z-base-32 public key.
std::optional<Key> FindPublicKey(const base::DictValue& dict,
                                 std::string_view key);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_JWS_H_

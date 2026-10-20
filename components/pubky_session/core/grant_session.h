// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_GRANT_SESSION_H_
#define COMPONENTS_PUBKY_SESSION_CORE_GRANT_SESSION_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/time/time.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"

// The homeserver side of a grant: proof of possession, the exchange request
// and the session it returns. The same request refreshes a bearer, and with
// DELETE logs out when the homeserver advertises grant-proof-logout.
namespace pubky_session {

inline constexpr char kGrantSessionPath[] = "/auth/grant/session";

// A proof-of-possession JWS (typ "pubky-pop") with claims `aud` (the
// homeserver key), `gid` (the grant ID), `nonce` and `iat`, signed with the
// client key whose public half is the grant's `cnf`. Each proof uses a fresh
// 16-byte random nonce.
std::string CreatePopProof(const Key& client_seed,
                           const Key& homeserver,
                           std::string_view grant_id,
                           base::Time now);
std::string CreatePopProofForTesting(const Key& client_seed,
                                     const Key& homeserver,
                                     std::string_view grant_id,
                                     base::Time now,
                                     std::string_view nonce);

// The JSON body {"grant": ..., "pop": ...}.
std::string CreateGrantSessionRequestBody(std::string_view grant_jws,
                                          std::string_view pop_proof);

// A GrantSessionResponse.
struct GrantSession {
  GrantSession();
  GrantSession(const GrantSession&);
  GrantSession& operator=(const GrantSession&);
  ~GrantSession();

  // The bearer for Authorization headers. Secret.
  std::string token;
  Key homeserver{};
  Key user{};
  std::string client_id;
  std::vector<Capability> capabilities;
  std::string grant_id;
  // Unix seconds.
  uint64_t token_expires_at = 0;
  uint64_t grant_expires_at = 0;
  uint64_t created_at = 0;
};

std::optional<GrantSession> ParseGrantSessionResponse(std::string_view json);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_GRANT_SESSION_H_

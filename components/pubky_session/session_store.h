// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_SESSION_STORE_H_
#define COMPONENTS_PUBKY_SESSION_SESSION_STORE_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "components/pubky_session/core/approval.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"

namespace pubky_session {

// The file in the profile directory that holds the encrypted session.
inline constexpr char kStorageFileName[] = "Pubky Session";

// Everything the browser keeps for its grant. All of it is secret except the
// keys and capabilities; the whole record is encrypted with the OS-backed
// key before it reaches disk.
struct StoredSession {
  StoredSession();
  StoredSession(const StoredSession&);
  StoredSession& operator=(const StoredSession&);
  ~StoredSession();

  // Seed of the proof-of-possession key bound by the grant's `cnf`.
  Key client_seed{};
  std::string grant_jws;
  Key user{};
  Key homeserver{};
  std::string grant_id;
  std::vector<Capability> capabilities;
  std::string bearer;
  // Unix seconds.
  uint64_t token_expires_at = 0;
  uint64_t grant_expires_at = 0;
  std::vector<EncryptionKey> encryption_keys;
};

std::string SerializeStoredSession(const StoredSession& session);
std::optional<StoredSession> ParseStoredSession(std::string_view json);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_SESSION_STORE_H_

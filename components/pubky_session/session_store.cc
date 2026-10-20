// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/session_store.h"

#include <utility>

#include "base/check.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"

namespace pubky_session {

namespace {

constexpr int kVersion = 1;

std::optional<Key> FindKey(const base::DictValue& dict, std::string_view key) {
  const std::string* text = dict.FindString(key);
  std::optional<std::string> bytes =
      text ? Base64UrlDecode(*text) : std::nullopt;
  return bytes ? KeyFromBytes(*bytes) : std::nullopt;
}

// Stored as strings: DictValue integers are 32-bit.
std::optional<uint64_t> FindTime(const base::DictValue& dict,
                                 std::string_view key) {
  const std::string* text = dict.FindString(key);
  uint64_t value = 0;
  if (!text || !base::StringToUint64(*text, &value)) {
    return std::nullopt;
  }
  return value;
}

}  // namespace

StoredSession::StoredSession() = default;
StoredSession::StoredSession(const StoredSession&) = default;
StoredSession& StoredSession::operator=(const StoredSession&) = default;
StoredSession::~StoredSession() = default;

std::string SerializeStoredSession(const StoredSession& session) {
  base::DictValue dict;
  dict.Set("version", kVersion);
  dict.Set("client_seed", Base64UrlEncode(KeyAsBytes(session.client_seed)));
  dict.Set("grant", session.grant_jws);
  dict.Set("user", EncodeZ32(session.user));
  dict.Set("homeserver", EncodeZ32(session.homeserver));
  dict.Set("grant_id", session.grant_id);
  dict.Set("capabilities", CapabilitiesToString(session.capabilities));
  dict.Set("bearer", session.bearer);
  dict.Set("token_expires_at",
           base::NumberToString(session.token_expires_at));
  dict.Set("grant_expires_at",
           base::NumberToString(session.grant_expires_at));
  base::ListValue keys;
  for (const EncryptionKey& key : session.encryption_keys) {
    keys.Append(base::DictValue()
                    .Set("scope", key.scope)
                    .Set("secret", Base64UrlEncode(KeyAsBytes(key.secret))));
  }
  dict.Set("encryption_keys", std::move(keys));
  std::optional<std::string> json = base::WriteJson(dict);
  CHECK(json);
  return std::move(*json);
}

std::optional<StoredSession> ParseStoredSession(std::string_view json) {
  std::optional<base::DictValue> dict =
      base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
  if (!dict || dict->FindInt("version") != kVersion) {
    return std::nullopt;
  }
  StoredSession session;
  std::optional<Key> client_seed = FindKey(*dict, "client_seed");
  const std::string* grant = dict->FindString("grant");
  const std::string* user = dict->FindString("user");
  const std::string* homeserver = dict->FindString("homeserver");
  const std::string* grant_id = dict->FindString("grant_id");
  const std::string* capabilities = dict->FindString("capabilities");
  const std::string* bearer = dict->FindString("bearer");
  std::optional<uint64_t> token_expires_at = FindTime(*dict, "token_expires_at");
  std::optional<uint64_t> grant_expires_at = FindTime(*dict, "grant_expires_at");
  const base::ListValue* keys = dict->FindList("encryption_keys");
  if (!client_seed || !grant || !user || !homeserver || !grant_id ||
      !capabilities || !bearer || !token_expires_at || !grant_expires_at ||
      !keys) {
    return std::nullopt;
  }
  std::optional<Key> user_key = DecodeZ32(*user);
  std::optional<Key> homeserver_key = DecodeZ32(*homeserver);
  std::optional<std::vector<Capability>> parsed_capabilities =
      ParseCapabilities(*capabilities);
  if (!user_key || !homeserver_key || !parsed_capabilities) {
    return std::nullopt;
  }
  for (const base::Value& entry : *keys) {
    const base::DictValue* key = entry.GetIfDict();
    const std::string* scope = key ? key->FindString("scope") : nullptr;
    std::optional<Key> secret = key ? FindKey(*key, "secret") : std::nullopt;
    if (!scope || !secret) {
      return std::nullopt;
    }
    session.encryption_keys.push_back({*scope, *secret});
  }
  session.client_seed = *client_seed;
  session.grant_jws = *grant;
  session.user = *user_key;
  session.homeserver = *homeserver_key;
  session.grant_id = *grant_id;
  session.capabilities = std::move(*parsed_capabilities);
  session.bearer = *bearer;
  session.token_expires_at = *token_expires_at;
  session.grant_expires_at = *grant_expires_at;
  return session;
}

}  // namespace pubky_session

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/grant_session.h"

#include <utility>

#include "base/check.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/json/string_escape.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "components/pubky_session/core/jws.h"

namespace pubky_session {

namespace {

constexpr size_t kNonceSize = 16;

std::string Quote(std::string_view value) {
  std::string out;
  base::EscapeJSONString(value, /*put_in_quotes=*/true, &out);
  return out;
}

}  // namespace

std::string CreatePopProofForTesting(const Key& client_seed,
                                     const Key& homeserver,
                                     std::string_view grant_id,
                                     base::Time now,
                                     std::string_view nonce) {
  // Written by hand so `iat` stays an integer past 2038; DictValue only holds
  // 32-bit integers. Keys are in the order serde writes PopProofClaims.
  std::string payload = "{\"aud\":" + Quote(EncodeZ32(homeserver)) +
                        ",\"gid\":" + Quote(grant_id) +
                        ",\"nonce\":" + Quote(nonce) + ",\"iat\":" +
                        base::NumberToString(now.ToTimeT()) + "}";
  return SignJws(kPopJwsType, payload, client_seed);
}

std::string CreatePopProof(const Key& client_seed,
                           const Key& homeserver,
                           std::string_view grant_id,
                           base::Time now) {
  return CreatePopProofForTesting(
      client_seed, homeserver, grant_id, now,
      Base64UrlEncode(base::RandBytesAsString(kNonceSize)));
}

std::string CreateGrantSessionRequestBody(std::string_view grant_jws,
                                          std::string_view pop_proof) {
  base::DictValue body;
  body.Set("grant", grant_jws);
  body.Set("pop", pop_proof);
  std::optional<std::string> json = base::WriteJson(body);
  CHECK(json);
  return std::move(*json);
}

GrantSession::GrantSession() = default;
GrantSession::GrantSession(const GrantSession&) = default;
GrantSession& GrantSession::operator=(const GrantSession&) = default;
GrantSession::~GrantSession() = default;

std::optional<GrantSession> ParseGrantSessionResponse(std::string_view json) {
  std::optional<base::DictValue> response =
      base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
  if (!response) {
    return std::nullopt;
  }
  const std::string* token = response->FindString("token");
  const base::DictValue* session = response->FindDict("session");
  if (!token || token->empty() || !session) {
    return std::nullopt;
  }
  std::optional<Key> homeserver = FindPublicKey(*session, "homeserver");
  std::optional<Key> user = FindPublicKey(*session, "pubky");
  const std::string* client_id = session->FindString("client_id");
  const std::string* grant_id = session->FindString("grant_id");
  const base::ListValue* capabilities = session->FindList("capabilities");
  std::optional<uint64_t> token_expires_at =
      FindUnsigned(*session, "token_expires_at");
  std::optional<uint64_t> grant_expires_at =
      FindUnsigned(*session, "grant_expires_at");
  std::optional<uint64_t> created_at = FindUnsigned(*session, "created_at");
  if (!homeserver || !user || !client_id || !grant_id || !capabilities ||
      !token_expires_at || !grant_expires_at || !created_at) {
    return std::nullopt;
  }

  GrantSession out;
  for (const base::Value& entry : *capabilities) {
    const std::string* text = entry.GetIfString();
    std::optional<Capability> capability =
        text ? ParseCapability(*text) : std::nullopt;
    if (!capability) {
      return std::nullopt;
    }
    out.capabilities.push_back(std::move(*capability));
  }
  out.token = *token;
  out.homeserver = *homeserver;
  out.user = *user;
  out.client_id = *client_id;
  out.grant_id = *grant_id;
  out.token_expires_at = *token_expires_at;
  out.grant_expires_at = *grant_expires_at;
  out.created_at = *created_at;
  return out;
}

}  // namespace pubky_session

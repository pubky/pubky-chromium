// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/test_vectors.h"

#include <utility>

#include "base/base64.h"
#include "base/base_paths.h"
#include "base/check.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/no_destructor.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "components/pubky_session/core/capabilities.h"

namespace pubky_session::test {

const base::DictValue& Vectors() {
  static const base::NoDestructor<base::DictValue> vectors([] {
    base::FilePath path;
    CHECK(base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path));
    path = path.AppendASCII("components")
               .AppendASCII("pubky_session")
               .AppendASCII("core")
               .AppendASCII("test_data")
               .AppendASCII("sdk_vectors.json");
    std::string json;
    CHECK(base::ReadFileToString(path, &json)) << path;
    std::optional<base::DictValue> dict =
        base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
    CHECK(dict);
    return std::move(*dict);
  }());
  return *vectors;
}

const std::string& VectorString(std::string_view path) {
  const std::string* value = Vectors().FindStringByDottedPath(path);
  CHECK(value) << path;
  return *value;
}

Key KeyFromHex(std::string_view hex) {
  Key key;
  CHECK(base::HexStringToSpan(hex, key)) << hex;
  return key;
}

Key KeyFromBase64Url(std::string_view text) {
  std::optional<std::string> bytes = Base64UrlDecode(text);
  CHECK(bytes);
  std::optional<Key> key = KeyFromBytes(*bytes);
  CHECK(key);
  return *key;
}

std::string DecodeBase64(std::string_view text) {
  std::string out;
  CHECK(base::Base64Decode(text, &out));
  return out;
}

Key UserSeed() {
  return KeyFromHex(VectorString("keys.user_secret_hex"));
}

Key UserPublicKey() {
  return KeyFromHex(VectorString("keys.user_public_hex"));
}

Key ClientSeed() {
  return KeyFromHex(VectorString("keys.client_secret_hex"));
}

Key HomeserverPublicKey() {
  std::optional<Key> key = DecodeZ32(VectorString("keys.homeserver_public_z32"));
  CHECK(key);
  return *key;
}

Key HpkePrivateKey() {
  return KeyFromBase64Url(VectorString("relay.hpke_recipient_secret_b64url"));
}

SigninGrantRequest BareRequest() {
  SigninGrantRequest request;
  request.capabilities = *ParseCapabilities(VectorString("bare_grant.caps"));
  request.relay = VectorString("relay.inbox");
  request.client_public_key = Ed25519PublicKey(ClientSeed());
  request.format = ApprovalFormat::kBareGrant;
  request.channel_key = KeyFromBase64Url(VectorString("relay.shared_secret_b64url"));
  return request;
}

SigninGrantRequest SignedRequest() {
  SigninGrantRequest request = BareRequest();
  request.capabilities =
      *ParseCapabilities(VectorString("signed_approval.caps"));
  request.format = ApprovalFormat::kSignedApprovalV1;
  request.channel_key =
      KeyFromBase64Url(VectorString("relay.hpke_recipient_public_b64url"));
  return request;
}

std::string BareRelayMessage() {
  return DecodeBase64(VectorString("bare_grant.relay_message_b64"));
}

std::string SignedRelayMessage() {
  return DecodeBase64(VectorString("signed_approval.relay_message_b64"));
}

}  // namespace pubky_session::test

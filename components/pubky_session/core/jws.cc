// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/jws.h"

#include <cmath>
#include <utility>

#include "base/check.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"

namespace pubky_session {

namespace {

constexpr char kAlgorithm[] = "EdDSA";

// 2^53: the largest range in which every integer is exact as a double.
constexpr double kMaxExactDouble = 9007199254740992.0;

std::optional<base::DictValue> DecodeJsonObject(std::string_view base64url) {
  std::optional<std::string> json = Base64UrlDecode(base64url);
  if (!json) {
    return std::nullopt;
  }
  return base::JSONReader::ReadDict(*json, base::JSON_PARSE_RFC);
}

}  // namespace

Jws::Jws() = default;
Jws::Jws(Jws&&) = default;
Jws& Jws::operator=(Jws&&) = default;
Jws::~Jws() = default;

std::optional<Jws> ParseJws(std::string_view compact) {
  const size_t first = compact.find('.');
  if (first == std::string_view::npos) {
    return std::nullopt;
  }
  const size_t second = compact.find('.', first + 1);
  if (second == std::string_view::npos ||
      compact.find('.', second + 1) != std::string_view::npos) {
    return std::nullopt;
  }

  std::optional<base::DictValue> header =
      DecodeJsonObject(compact.substr(0, first));
  if (!header) {
    return std::nullopt;
  }
  const std::string* algorithm = header->FindString("alg");
  const std::string* type = header->FindString("typ");
  if (!algorithm || *algorithm != kAlgorithm || !type) {
    return std::nullopt;
  }

  std::optional<base::DictValue> payload =
      DecodeJsonObject(compact.substr(first + 1, second - first - 1));
  std::optional<std::string> signature =
      Base64UrlDecode(compact.substr(second + 1));
  if (!payload || !signature || signature->size() != kSignatureSize) {
    return std::nullopt;
  }

  Jws jws;
  jws.type = *type;
  jws.payload = std::move(*payload);
  jws.signing_input = std::string(compact.substr(0, second));
  jws.signature = std::move(*signature);
  return jws;
}

bool VerifyJws(const Jws& jws, const Key& signer) {
  return Ed25519Verify(signer, jws.signing_input, jws.signature);
}

std::string SignJws(std::string_view type,
                    std::string_view payload_json,
                    const Key& seed) {
  base::DictValue header;
  header.Set("alg", kAlgorithm);
  header.Set("typ", type);
  // DictValue keeps keys sorted, so this matches the SDK's {"alg","typ"}.
  std::optional<std::string> header_json = base::WriteJson(header);
  CHECK(header_json);

  std::string signing_input = Base64UrlEncode(*header_json);
  signing_input.push_back('.');
  signing_input.append(Base64UrlEncode(payload_json));
  const Signature signature = Ed25519Sign(seed, signing_input);

  std::string compact = signing_input;
  compact.push_back('.');
  compact.append(
      Base64UrlEncode(std::string(signature.begin(), signature.end())));
  return compact;
}

std::optional<uint64_t> FindUnsigned(const base::DictValue& dict,
                                     std::string_view key) {
  if (std::optional<int> value = dict.FindInt(key)) {
    if (*value < 0) {
      return std::nullopt;
    }
    return static_cast<uint64_t>(*value);
  }
  // The JSON reader stores integers above INT_MAX as doubles.
  if (std::optional<double> value = dict.FindDouble(key)) {
    if (*value < 0 || *value > kMaxExactDouble ||
        std::floor(*value) != *value) {
      return std::nullopt;
    }
    return static_cast<uint64_t>(*value);
  }
  return std::nullopt;
}

std::optional<Key> FindPublicKey(const base::DictValue& dict,
                                 std::string_view key) {
  const std::string* text = dict.FindString(key);
  if (!text) {
    return std::nullopt;
  }
  return DecodeZ32(*text);
}

}  // namespace pubky_session

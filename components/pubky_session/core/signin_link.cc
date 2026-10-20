// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/signin_link.h"

#include <stdint.h>

namespace pubky_session {

namespace {

void AppendParam(std::string& link,
                 bool& first,
                 std::string_view name,
                 std::string_view value) {
  link.push_back(first ? '?' : '&');
  first = false;
  link.append(name);
  link.push_back('=');
  link.append(FormUrlEncode(value));
}

}  // namespace

std::string FormUrlEncode(std::string_view value) {
  constexpr std::string_view kHex = "0123456789ABCDEF";
  std::string out;
  out.reserve(value.size());
  for (char c : value) {
    const uint8_t byte = static_cast<uint8_t>(c);
    if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9') || byte == '*' || byte == '-' ||
        byte == '.' || byte == '_') {
      out.push_back(c);
    } else if (byte == ' ') {
      out.push_back('+');
    } else {
      out.push_back('%');
      out.push_back(kHex[byte >> 4]);
      out.push_back(kHex[byte & 15]);
    }
  }
  return out;
}

std::string BuildSigninGrantLink(const SigninGrantRequest& request) {
  std::string link = "pubkyauth://signin_grant";
  bool first = true;
  AppendParam(link, first, "caps",
              CapabilitiesToString(request.capabilities));
  AppendParam(link, first, "relay", request.relay);
  AppendParam(link, first, "cid", request.client_id);
  AppendParam(link, first, "cpk", EncodeZ32(request.client_public_key));
  const std::string channel_key =
      Base64UrlEncode(KeyAsBytes(request.channel_key));
  if (request.format == ApprovalFormat::kSignedApprovalV1) {
    AppendParam(link, first, "af", "v1");
    AppendParam(link, first, "epk", channel_key);
  } else {
    AppendParam(link, first, "secret", channel_key);
  }
  return link;
}

std::string RelayChannelId(const SigninGrantRequest& request) {
  return request.format == ApprovalFormat::kSignedApprovalV1
             ? HpkeChannelId(request.channel_key)
             : SharedSecretChannelId(request.channel_key);
}

std::string RelayChannelUrl(const SigninGrantRequest& request) {
  std::string url = request.relay;
  if (!url.ends_with('/')) {
    url.push_back('/');
  }
  url.append(RelayChannelId(request));
  return url;
}

}  // namespace pubky_session

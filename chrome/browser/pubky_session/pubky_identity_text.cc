// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/pubky_session/pubky_identity_text.h"

#include <optional>
#include <string>

#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "chrome/grit/generated_resources.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/base/l10n/l10n_util.h"

std::u16string ShortPubkyKey(const pubky_session::Key& key) {
  const std::string z32 = pubky_session::EncodeZ32(key);
  return base::UTF8ToUTF16(z32.substr(0, 4)) + u"…" +
         base::UTF8ToUTF16(z32.substr(z32.size() - 4));
}

std::u16string PubkyIdentityLabel(
    const pubky_session::PubkySessionService& service) {
  if (std::optional<std::string> name = service.display_name()) {
    return base::UTF8ToUTF16(*name);
  }
  if (std::optional<pubky_session::Key> user = service.user()) {
    return ShortPubkyKey(*user);
  }
  return std::u16string();
}

bool IsPrivateScope(const pubky_session::Capability& scope) {
  return !scope.scope.starts_with("/pub/");
}

std::u16string DescribeScope(const pubky_session::Capability& scope) {
  const bool is_private = IsPrivateScope(scope);
  int message_id;
  if (scope.read && scope.write) {
    message_id = is_private ? IDS_PUBKY_SCOPE_PRIVATE_READ_WRITE
                            : IDS_PUBKY_SCOPE_READ_WRITE;
  } else if (scope.write) {
    message_id =
        is_private ? IDS_PUBKY_SCOPE_PRIVATE_WRITE : IDS_PUBKY_SCOPE_WRITE;
  } else {
    message_id =
        is_private ? IDS_PUBKY_SCOPE_PRIVATE_READ : IDS_PUBKY_SCOPE_READ;
  }
  return l10n_util::GetStringFUTF16(message_id,
                                    base::UTF8ToUTF16(scope.scope));
}

std::u16string DescribeScopes(
    const std::vector<pubky_session::Capability>& scopes) {
  std::vector<std::u16string> descriptions;
  for (const pubky_session::Capability& scope : scopes) {
    descriptions.push_back(DescribeScope(scope));
  }
  return base::JoinString(descriptions, u", ");
}

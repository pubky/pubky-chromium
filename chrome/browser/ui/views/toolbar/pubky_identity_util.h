// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_

#include <string>
#include <string_view>
#include <vector>

#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/base/models/image_model.h"

namespace pubky_session {
class PubkySessionService;
}  // namespace pubky_session

// The Pubky accent and base colors, as in //chrome/browser/ui/color's Pubky
// mixer.
inline constexpr SkColor kPubkyAccentColor = SkColorSetRGB(0xC8, 0xFF, 0x00);
inline constexpr SkColor kPubkyDarkColor = SkColorSetRGB(0x05, 0x05, 0x0A);
inline constexpr SkColor kPubkyAttentionColor = SkColorSetRGB(0xF5, 0xA5, 0x24);

// A round avatar on the accent color with the first letter of `label`.
ui::ImageModel PubkyIdentityAvatar(std::u16string_view label, int size);

// "8um7…1dty": the first and last four characters of a key's z-base-32 form.
std::u16string ShortPubkyKey(const pubky_session::Key& key);

// The name from the user's profile, or the short key.
std::u16string PubkyIdentityLabel(
    const pubky_session::PubkySessionService& service);

// Whether `scope` is outside public storage, /pub/.
bool IsPrivateScope(const pubky_session::Capability& scope);

// "Read and write /pub/example.com/", or "Private storage · read
// /priv/notes/" for scopes outside /pub/.
std::u16string DescribeScope(const pubky_session::Capability& scope);

// Every scope described, separated by commas.
std::u16string DescribeScopes(
    const std::vector<pubky_session::Capability>& scopes);

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_

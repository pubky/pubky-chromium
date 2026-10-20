// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_

#include <string_view>

#include "third_party/skia/include/core/SkColor.h"
#include "ui/base/models/image_model.h"

// The Pubky accent and base colors, as in //chrome/browser/ui/color's Pubky
// mixer.
inline constexpr SkColor kPubkyAccentColor = SkColorSetRGB(0xC8, 0xFF, 0x00);
inline constexpr SkColor kPubkyDarkColor = SkColorSetRGB(0x05, 0x05, 0x0A);
inline constexpr SkColor kPubkyAttentionColor = SkColorSetRGB(0xF5, 0xA5, 0x24);

// A round avatar on the accent color with the first letter of `label`.
ui::ImageModel PubkyIdentityAvatar(std::u16string_view label, int size);

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UTIL_H_

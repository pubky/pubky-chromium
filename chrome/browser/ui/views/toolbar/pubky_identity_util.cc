// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/i18n/case_conversion.h"
#include "base/strings/utf_string_conversions.h"
#include "cc/paint/paint_flags.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/gfx/canvas.h"
#include "ui/gfx/font_list.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/image/canvas_image_source.h"
#include "ui/gfx/image/image_skia.h"

namespace {

class InitialAvatarSource : public gfx::CanvasImageSource {
 public:
  InitialAvatarSource(std::u16string initial, int size)
      : gfx::CanvasImageSource(gfx::Size(size, size)),
        initial_(std::move(initial)) {}

  // gfx::CanvasImageSource:
  void Draw(gfx::Canvas* canvas) override {
    const float radius = size().width() / 2.0f;
    cc::PaintFlags flags;
    flags.setAntiAlias(true);
    flags.setColor(kPubkyAccentColor);
    canvas->DrawCircle(gfx::PointF(radius, radius), radius, flags);

    const gfx::FontList base_font;
    const int target_size = std::max(8, size().height() * 9 / 20);
    const gfx::FontList font =
        base_font.DeriveWithSizeDelta(target_size - base_font.GetFontSize())
            .DeriveWithWeight(gfx::Font::Weight::BOLD);
    canvas->DrawStringRectWithFlags(initial_, font, kPubkyDarkColor,
                                    gfx::Rect(size()),
                                    gfx::Canvas::TEXT_ALIGN_CENTER);
  }

 private:
  const std::u16string initial_;
};

}  // namespace

ui::ImageModel PubkyIdentityAvatar(std::u16string_view label, int size) {
  std::u16string initial = u"?";
  if (!label.empty()) {
    initial = base::i18n::ToUpper(label.substr(0, 1));
  }
  return ui::ImageModel::FromImageSkia(
      gfx::ImageSkia(std::make_unique<InitialAvatarSource>(initial, size),
                     gfx::Size(size, size)));
}

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

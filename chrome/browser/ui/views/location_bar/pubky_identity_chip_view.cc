// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/location_bar/pubky_identity_chip_view.h"

#include <optional>
#include <string>
#include <utility>

#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/grit/generated_resources.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/views/border.h"

namespace {

constexpr int kAvatarSize = 16;
constexpr int kCornerRadius = 12;
constexpr auto kPadding = gfx::Insets::TLBR(2, 4, 2, 10);

}  // namespace

PubkyIdentityChipView::PubkyIdentityChipView(
    base::RepeatingClosure open_page_info)
    : LabelButton(std::move(open_page_info)) {
  SetBorder(views::CreatePaddedBorder(
      views::CreateRoundedRectBorder(1, kCornerRadius, kPubkyAccentColor),
      kPadding));
  SetImageLabelSpacing(6);
  SetVisible(false);
}

PubkyIdentityChipView::~PubkyIdentityChipView() = default;

void PubkyIdentityChipView::Update(content::WebContents* contents) {
  contents_ = contents ? contents->GetWeakPtr() : nullptr;
  // A location bar belongs to one window, so to one profile.
  if (contents && !settings_) {
    Profile* profile =
        Profile::FromBrowserContext(contents->GetBrowserContext());
    service_ = PubkySessionServiceFactory::GetForProfile(profile);
    settings_ = HostContentSettingsMapFactory::GetForProfile(profile);
    if (service_) {
      service_observation_.Observe(service_.get());
    }
    settings_observation_.Observe(settings_.get());
  }
  Refresh();
}

void PubkyIdentityChipView::OnPubkySessionChanged() {
  Refresh();
}

void PubkyIdentityChipView::OnContentSettingChanged(
    const ContentSettingsPattern& primary_pattern,
    const ContentSettingsPattern& secondary_pattern,
    ContentSettingsTypeSet content_type_set) {
  if (content_type_set.Contains(ContentSettingsType::PUBKY_SITE_ACCESS)) {
    Refresh();
  }
}

void PubkyIdentityChipView::Refresh() {
  content::WebContents* contents = contents_.get();
  std::optional<pubky_session::Key> user =
      service_ ? service_->user() : std::nullopt;
  const bool connected =
      contents && user &&
      !pubky_session::GetSiteScopes(
           settings_,
           contents->GetPrimaryMainFrame()->GetLastCommittedOrigin(), *user)
           .empty();
  if (connected) {
    const std::u16string identity = PubkyIdentityLabel(*service_);
    SetText(identity);
    SetImageModel(views::Button::STATE_NORMAL,
                  PubkyIdentityAvatar(identity, kAvatarSize));
    SetTooltipText(
        l10n_util::GetStringFUTF16(IDS_PUBKY_CHIP_TOOLTIP, identity));
  }
  SetVisible(connected);
}

BEGIN_METADATA(PubkyIdentityChipView)
END_METADATA

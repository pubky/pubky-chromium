// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/page_info/pubky_page_info_section.h"

#include <memory>
#include <optional>
#include <string>

#include "base/functional/bind.h"
#include "base/i18n/time_formatting.h"
#include "base/time/time.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_identity_text.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/grit/generated_resources.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/url_formatter/elide_url.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/views/accessibility/view_accessibility.h"
#include "ui/views/controls/button/md_text_button.h"
#include "ui/views/controls/image_view.h"
#include "ui/views/controls/label.h"
#include "ui/views/controls/separator.h"
#include "ui/views/layout/box_layout.h"
#include "ui/views/style/typography.h"
#include "ui/views/view_class_properties.h"
#include "url/gurl.h"

namespace {

constexpr int kAvatarSize = 28;

std::unique_ptr<views::Label> MakeLabel(const std::u16string& text,
                                        int style) {
  auto label = std::make_unique<views::Label>(
      text, views::style::CONTEXT_DIALOG_BODY_TEXT, style);
  label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  return label;
}

std::u16string AccessText(const pubky_session::SiteAccess& access) {
  const std::u16string scopes = DescribeScopes(access.scopes);
  if (access.since.is_null() ||
      access.since.LocalMidnight() == base::Time::Now().LocalMidnight()) {
    return l10n_util::GetStringFUTF16(IDS_PUBKY_PAGE_INFO_ACCESS_SINCE_TODAY,
                                      scopes);
  }
  return l10n_util::GetStringFUTF16(IDS_PUBKY_PAGE_INFO_ACCESS_SINCE, scopes,
                                    base::TimeFormatShortDate(access.since));
}

}  // namespace

DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkyPageInfoSection, kSectionElementId);
DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkyPageInfoSection,
                                      kDisconnectElementId);

PubkyPageInfoSection::PubkyPageInfoSection(content::WebContents* contents,
                                           const GURL& site_url)
    : origin_(url::Origin::Create(site_url)) {
  SetProperty(views::kElementIdentifierKey, kSectionElementId);
  SetVisible(false);
  Profile* profile =
      contents ? Profile::FromBrowserContext(contents->GetBrowserContext())
               : nullptr;
  pubky_session::PubkySessionService* service =
      profile ? PubkySessionServiceFactory::GetForProfile(profile) : nullptr;
  if (!service || !service->user()) {
    return;
  }
  settings_ = HostContentSettingsMapFactory::GetForProfile(profile);
  std::optional<pubky_session::SiteAccess> access =
      pubky_session::GetSiteAccess(settings_, origin_, *service->user());
  if (!access) {
    return;
  }
  SetVisible(true);

  ChromeLayoutProvider* layout_provider = ChromeLayoutProvider::Get();
  const int horizontal = layout_provider->GetDistanceMetric(
      DISTANCE_HORIZONTAL_SEPARATOR_PADDING_PAGE_INFO_VIEW);
  const int vertical = layout_provider->GetDistanceMetric(
      views::DISTANCE_RELATED_CONTROL_VERTICAL);
  auto* layout = SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical,
      gfx::Insets::TLBR(0, horizontal, vertical, horizontal), vertical));
  layout->set_cross_axis_alignment(
      views::BoxLayout::CrossAxisAlignment::kStretch);

  AddChildView(std::make_unique<views::Separator>());
  AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_PAGE_INFO_HEADER),
                views::style::STYLE_SECONDARY));

  const std::u16string identity = PubkyIdentityLabel(*service);
  auto* row = AddChildView(std::make_unique<views::View>());
  row->SetLayoutManager(std::make_unique<views::BoxLayout>(
                            views::BoxLayout::Orientation::kHorizontal,
                            gfx::Insets(),
                            layout_provider->GetDistanceMetric(
                                views::DISTANCE_RELATED_LABEL_HORIZONTAL)))
      ->set_cross_axis_alignment(views::BoxLayout::CrossAxisAlignment::kCenter);
  row->AddChildView(std::make_unique<views::ImageView>(
      PubkyIdentityAvatar(identity, kAvatarSize)));
  auto* text = row->AddChildView(std::make_unique<views::View>());
  text->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical));
  text->AddChildView(MakeLabel(
      l10n_util::GetStringFUTF16(IDS_PUBKY_PAGE_INFO_CONNECTED_AS, identity),
      views::style::STYLE_PRIMARY));
  text->AddChildView(MakeLabel(AccessText(*access),
                               views::style::STYLE_SECONDARY));

  // In a row of its own so that it keeps its natural width.
  auto* button_row = AddChildView(std::make_unique<views::View>());
  button_row->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kHorizontal));
  auto* disconnect = button_row->AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyPageInfoSection::Disconnect,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_PAGE_INFO_DISCONNECT)));
  disconnect->SetProperty(views::kElementIdentifierKey, kDisconnectElementId);
  disconnect->GetViewAccessibility().SetName(l10n_util::GetStringFUTF16(
      IDS_PUBKY_PAGE_INFO_DISCONNECT_ACCESSIBLE_NAME,
      url_formatter::FormatOriginForSecurityDisplay(
          origin_, url_formatter::SchemeDisplay::OMIT_HTTP_AND_HTTPS)));
}

PubkyPageInfoSection::~PubkyPageInfoSection() = default;

void PubkyPageInfoSection::Disconnect() {
  pubky_session::RemoveSiteAccess(settings_, origin_);
  // The site's next call fails; nothing else here changes.
  SetVisible(false);
}

BEGIN_METADATA(PubkyPageInfoSection)
END_METADATA

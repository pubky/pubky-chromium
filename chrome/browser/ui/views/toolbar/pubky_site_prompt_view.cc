// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_site_prompt_view.h"

#include <memory>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_identity_text.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/browser/ui/views/bubble_anchor_util_views.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/grit/theme_resources.h"
#include "components/qr_code_generator/bitmap_generator.h"
#include "components/tabs/public/tab_interface.h"
#include "components/url_formatter/elide_url.h"
#include "components/vector_icons/vector_icons.h"
#include "content/public/browser/visibility.h"
#include "content/public/browser/web_contents.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/base/mojom/dialog_button.mojom.h"
#include "ui/color/color_id.h"
#include "ui/views/accessibility/view_accessibility.h"
#include "ui/views/controls/image_view.h"
#include "ui/views/controls/label.h"
#include "ui/views/layout/box_layout.h"
#include "ui/views/style/typography.h"
#include "ui/views/vector_icons.h"
#include "ui/views/view_class_properties.h"
#include "ui/views/widget/widget.h"

namespace {

using pubky_session::Capability;

constexpr int kPromptWidth = 380;
constexpr int kHeaderIconSize = 22;
constexpr int kAvatarSize = 28;
constexpr int kScopeIconSize = 16;
constexpr int kQrCodeSize = 104;

// The open prompt shown last.
PubkySitePromptView* g_prompt = nullptr;

std::unique_ptr<views::View> Row() {
  auto row = std::make_unique<views::View>();
  auto* layout = row->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kHorizontal, gfx::Insets(),
      ChromeLayoutProvider::Get()->GetDistanceMetric(
          views::DISTANCE_RELATED_LABEL_HORIZONTAL)));
  layout->set_cross_axis_alignment(
      views::BoxLayout::CrossAxisAlignment::kCenter);
  return row;
}

std::unique_ptr<views::View> Column() {
  auto column = std::make_unique<views::View>();
  column->SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical));
  return column;
}

std::unique_ptr<views::Label> MakeLabel(const std::u16string& text,
                                        int style,
                                        bool multi_line = false) {
  auto label = std::make_unique<views::Label>(
      text, views::style::CONTEXT_DIALOG_BODY_TEXT, style);
  label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  label->SetMultiLine(multi_line);
  return label;
}

}  // namespace

DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkySitePromptView, kQrCodeElementId);

// static
void PubkySitePromptView::ShowAccessPrompt(
    content::WebContents* contents,
    const url::Origin& origin,
    const std::vector<Capability>& scopes,
    base::OnceCallback<void(bool allowed)> callback) {
  Show(contents, origin, scopes, /*ring=*/false, std::move(callback));
}

// static
void PubkySitePromptView::ShowRingPrompt(
    content::WebContents* contents,
    const url::Origin& origin,
    const std::vector<Capability>& scopes) {
  Show(contents, origin, scopes, /*ring=*/true, base::NullCallback());
}

// static
PubkySitePromptView* PubkySitePromptView::GetForTesting() {
  return g_prompt;
}

// static
void PubkySitePromptView::Show(content::WebContents* contents,
                               const url::Origin& origin,
                               const std::vector<Capability>& scopes,
                               bool ring,
                               base::OnceCallback<void(bool allowed)> callback) {
  tabs::TabInterface* tab =
      contents ? tabs::TabInterface::MaybeGetFromContents(contents) : nullptr;
  pubky_session::PubkySessionService* service =
      contents ? PubkySessionServiceFactory::GetForProfile(
                     Profile::FromBrowserContext(contents->GetBrowserContext()))
               : nullptr;
  // The prompt anchors to the address bar, so only the tab in front can ask.
  if (!tab || !tab->IsActivated() || !service || !service->user()) {
    if (ring && service) {
      service->CancelSignIn();
    }
    if (callback) {
      std::move(callback).Run(false);
    }
    return;
  }
  bubble_anchor_util::AnchorConfiguration anchor =
      bubble_anchor_util::GetPageInfoAnchorConfiguration(
          tab->GetBrowserWindowInterface());
  g_prompt = new PubkySitePromptView(anchor.anchor, anchor.bubble_arrow,
                                     contents, service, origin, scopes, ring,
                                     std::move(callback));
  // Owned as the base class, whose destructor is public.
  views::BubbleDialogDelegateView::CreateBubble(
      std::unique_ptr<views::BubbleDialogDelegateView>(g_prompt))
      ->Show();
}

PubkySitePromptView::PubkySitePromptView(
    views::BubbleAnchor anchor,
    views::BubbleBorder::Arrow arrow,
    content::WebContents* contents,
    pubky_session::PubkySessionService* service,
    const url::Origin& origin,
    const std::vector<Capability>& scopes,
    bool ring,
    base::OnceCallback<void(bool allowed)> callback)
    : BubbleDialogDelegateView(anchor, arrow),
      content::WebContentsObserver(contents),
      ring_(ring),
      service_(service),
      ring_link_(ring ? service->scope_approval_link() : std::string()),
      callback_(std::move(callback)) {
  set_fixed_width(kPromptWidth);
  set_margins(
      ChromeLayoutProvider::Get()->GetInsetsMetric(views::INSETS_DIALOG));
  auto* layout = SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      ChromeLayoutProvider::Get()->GetDistanceMetric(
          views::DISTANCE_RELATED_CONTROL_VERTICAL)));
  layout->set_cross_axis_alignment(
      views::BoxLayout::CrossAxisAlignment::kStretch);

  if (ring_) {
    SetButtons(static_cast<int>(ui::mojom::DialogButton::kCancel));
    SetButtonLabel(ui::mojom::DialogButton::kCancel,
                   l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_CANCEL));
  } else {
    SetButtons(static_cast<int>(ui::mojom::DialogButton::kOk) |
               static_cast<int>(ui::mojom::DialogButton::kCancel));
    SetButtonLabel(ui::mojom::DialogButton::kOk,
                   l10n_util::GetStringUTF16(IDS_PUBKY_SITE_PROMPT_ALLOW));
    SetButtonLabel(ui::mojom::DialogButton::kCancel,
                   l10n_util::GetStringUTF16(IDS_PUBKY_SITE_PROMPT_DENY));
    SetAcceptCallback(base::BindOnce(&PubkySitePromptView::Finish,
                                     base::Unretained(this), true));
  }
  // As with permission prompts, Enter does not grant access.
  SetDefaultButton(static_cast<int>(ui::mojom::DialogButton::kNone));
  SetCancelCallback(base::BindOnce(&PubkySitePromptView::Finish,
                                   base::Unretained(this), false));
  SetCloseCallback(base::BindOnce(&PubkySitePromptView::Finish,
                                  base::Unretained(this), false));

  HostContentSettingsMap* settings = HostContentSettingsMapFactory::GetForProfile(
      Profile::FromBrowserContext(contents->GetBrowserContext()));
  const bool connected =
      !pubky_session::GetSiteScopes(settings, origin, *service_->user())
           .empty();
  AddContents(origin, scopes, connected);
  if (ring_) {
    AddRingApproval();
  }
  observation_.Observe(service_.get());
}

PubkySitePromptView::~PubkySitePromptView() {
  if (g_prompt == this) {
    g_prompt = nullptr;
  }
  if (callback_) {
    std::move(callback_).Run(false);
  }
}

void PubkySitePromptView::PrimaryPageChanged(content::Page& page) {
  CloseWidget();
}

void PubkySitePromptView::OnVisibilityChanged(
    content::Visibility visibility) {
  if (visibility == content::Visibility::HIDDEN) {
    CloseWidget();
  }
}

void PubkySitePromptView::WebContentsDestroyed() {
  Observe(nullptr);
  CloseWidget();
}

void PubkySitePromptView::OnPubkySessionChanged() {
  if (ring_) {
    // Approved, refused or cancelled in Ring.
    if (service_->scope_approval_link() != ring_link_) {
      CloseWidget();
    }
    return;
  }
  if (!service_->user()) {
    CloseWidget();
  }
}

void PubkySitePromptView::AddContents(const url::Origin& origin,
                                      const std::vector<Capability>& scopes,
                                      bool connected) {
  const std::u16string site = url_formatter::FormatOriginForSecurityDisplay(
      origin, url_formatter::SchemeDisplay::OMIT_HTTP_AND_HTTPS);
  const std::u16string identity = PubkyIdentityLabel(*service_);
  const std::u16string title = l10n_util::GetStringFUTF16(
      connected ? IDS_PUBKY_SITE_PROMPT_MORE_TITLE : IDS_PUBKY_SITE_PROMPT_TITLE,
      site);
  SetAccessibleTitle(title);

  views::View* header = AddChildView(Row());
  auto* logo = header->AddChildView(std::make_unique<views::ImageView>(
      ui::ImageModel::FromResourceId(IDR_PRODUCT_LOGO_16)));
  logo->SetImageSize(gfx::Size(kHeaderIconSize, kHeaderIconSize));
  views::Label* title_label = header->AddChildView(std::make_unique<views::Label>(
      title, views::style::CONTEXT_DIALOG_TITLE, views::style::STYLE_PRIMARY));
  title_label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  title_label->SetMultiLine(true);
  static_cast<views::BoxLayout*>(header->GetLayoutManager())
      ->SetFlexForView(title_label, 1);

  if (connected) {
    AddChildView(MakeLabel(
        l10n_util::GetStringFUTF16(IDS_PUBKY_SITE_PROMPT_CONNECTED, identity),
        views::style::STYLE_SECONDARY, /*multi_line=*/true));
  } else {
    views::View* card = AddChildView(Row());
    card->AddChildView(std::make_unique<views::ImageView>(
        PubkyIdentityAvatar(identity, kAvatarSize)));
    views::View* text = card->AddChildView(Column());
    text->AddChildView(MakeLabel(identity, views::style::STYLE_PRIMARY));
    text->AddChildView(MakeLabel(ShortPubkyKey(*service_->user()),
                                 views::style::STYLE_SECONDARY));
    if (ring_) {
      AddChildView(
          MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_SITE_PROMPT_ASKS),
                    views::style::STYLE_SECONDARY));
    }
  }

  for (const Capability& scope : scopes) {
    views::View* row = AddChildView(Row());
    row->AddChildView(
        std::make_unique<views::ImageView>(ui::ImageModel::FromVectorIcon(
            IsPrivateScope(scope) ? vector_icons::kLockIcon : views::kCheckIcon,
            ui::kColorIcon, kScopeIconSize)));
    row->AddChildView(
        MakeLabel(DescribeScope(scope), views::style::STYLE_PRIMARY));
  }

  if (!ring_) {
    AddChildView(MakeLabel(
        l10n_util::GetStringUTF16(IDS_PUBKY_SITE_PROMPT_FOOTNOTE),
        views::style::STYLE_SECONDARY, /*multi_line=*/true));
  }
}

void PubkySitePromptView::AddRingApproval() {
  views::View* row = AddChildView(Row());
  base::expected<gfx::ImageSkia, qr_code_generator::Error> qr_code =
      qr_code_generator::GenerateImage(
          base::as_byte_span(ring_link_),
          qr_code_generator::ModuleStyle::kSquares,
          qr_code_generator::LocatorStyle::kRounded,
          qr_code_generator::CenterImage::kProductLogo,
          qr_code_generator::QuietZone::kIncluded);
  if (qr_code.has_value()) {
    auto* image = row->AddChildView(std::make_unique<views::ImageView>(
        ui::ImageModel::FromImageSkia(*qr_code)));
    image->SetImageSize(gfx::Size(kQrCodeSize, kQrCodeSize));
    image->SetProperty(views::kElementIdentifierKey, kQrCodeElementId);
    image->GetViewAccessibility().SetName(
        l10n_util::GetStringUTF16(IDS_PUBKY_RING_PROMPT_QR_ACCESSIBLE_NAME));
  }
  views::View* text = row->AddChildView(Column());
  text->AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_RING_PROMPT_TITLE),
                views::style::STYLE_PRIMARY));
  text->AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_RING_PROMPT_BODY),
                views::style::STYLE_SECONDARY, /*multi_line=*/true));
  static_cast<views::BoxLayout*>(row->GetLayoutManager())
      ->SetFlexForView(text, 1);
}

void PubkySitePromptView::Finish(bool allowed) {
  if (ring_) {
    // Closing the prompt cancels the approval it shows, unless it ended.
    if (!ring_link_.empty() &&
        service_->scope_approval_link() == ring_link_) {
      service_->CancelSignIn();
    }
    return;
  }
  if (callback_) {
    std::move(callback_).Run(allowed);
  }
}

void PubkySitePromptView::CloseWidget() {
  if (GetWidget()) {
    GetWidget()->Close();
  }
}

BEGIN_METADATA(PubkySitePromptView)
END_METADATA

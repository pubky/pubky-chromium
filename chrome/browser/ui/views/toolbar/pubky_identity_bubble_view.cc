// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_identity_bubble_view.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/strings/escape.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/profiles/profile_attributes_entry.h"
#include "chrome/browser/profiles/profile_attributes_storage.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/profiles/profile_window.h"
#include "chrome/browser/pubky_session/pubky_identity_text.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface.h"
#include "chrome/browser/ui/browser_tabstrip.h"
#include "chrome/browser/ui/chrome_pages.h"
#include "chrome/browser/ui/views/chrome_layout_provider.h"
#include "chrome/browser/ui/views/controls/hover_button.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/grit/theme_resources.h"
#include "components/pubky_session/core/crypto.h"
#include "components/qr_code_generator/bitmap_generator.h"
#include "components/vector_icons/vector_icons.h"
#include "ui/base/clipboard/scoped_clipboard_writer.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/base/mojom/dialog_button.mojom.h"
#include "ui/base/page_transition_types.h"
#include "ui/views/accessibility/view_accessibility.h"
#include "ui/views/background.h"
#include "ui/views/border.h"
#include "ui/views/controls/button/image_button.h"
#include "ui/views/controls/button/image_button_factory.h"
#include "ui/views/controls/button/md_text_button.h"
#include "ui/views/controls/image_view.h"
#include "ui/views/controls/label.h"
#include "ui/views/controls/link.h"
#include "ui/views/controls/separator.h"
#include "ui/views/layout/box_layout.h"
#include "ui/views/style/typography.h"
#include "ui/views/view_class_properties.h"
#include "ui/views/widget/widget.h"
#include "url/gurl.h"

namespace {

using State = pubky_session::PubkySessionService::State;
using SignInResult = pubky_session::PubkySessionService::SignInResult;

constexpr int kBubbleWidth = 360;
constexpr int kQrCodeSize = 176;
constexpr int kLogoSize = 28;
constexpr int kRowAvatarSize = 28;
constexpr int kCopyIconSize = 16;
constexpr SkColor kAttentionBackground = SkColorSetRGB(0xFF, 0xF1, 0xD6);
constexpr char kPassportAuthorizeUrl[] =
    "https://passport.pubky.app/authorize#d=";
constexpr char kRingDownloadUrl[] = "https://pubkyring.app";

// The open panel, if any. Only one exists at a time.
PubkyIdentityBubbleView* g_bubble = nullptr;

std::optional<int> ErrorMessageId(std::optional<SignInResult> result) {
  if (!result) {
    return std::nullopt;
  }
  switch (*result) {
    case SignInResult::kTimedOut:
      return IDS_PUBKY_IDENTITY_ERROR_TIMED_OUT;
    case SignInResult::kRejected:
      return IDS_PUBKY_IDENTITY_ERROR_REJECTED;
    case SignInResult::kHomeserverNotFound:
      return IDS_PUBKY_IDENTITY_ERROR_HOMESERVER;
    case SignInResult::kExchangeFailed:
      return IDS_PUBKY_IDENTITY_ERROR_EXCHANGE;
    case SignInResult::kNetworkError:
      return IDS_PUBKY_IDENTITY_ERROR_NETWORK;
    case SignInResult::kSignedIn:
    case SignInResult::kCancelled:
      return std::nullopt;
  }
}

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
                                        int context,
                                        int style) {
  auto label = std::make_unique<views::Label>(text, context, style);
  label->SetHorizontalAlignment(gfx::ALIGN_LEFT);
  return label;
}

}  // namespace

DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkyIdentityBubbleView,
                                      kQrCodeElementId);
DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkyIdentityBubbleView,
                                      kSignOutElementId);
DEFINE_CLASS_ELEMENT_IDENTIFIER_VALUE(PubkyIdentityBubbleView,
                                      kPassportElementId);

// static
void PubkyIdentityBubbleView::Show(views::Button* anchor, BrowserWindowInterface* browser) {
  if (g_bubble) {
    return;
  }
  g_bubble = new PubkyIdentityBubbleView(anchor, browser);
  // Owned as the base class, whose destructor is public.
  views::BubbleDialogDelegateView::CreateBubble(
      std::unique_ptr<views::BubbleDialogDelegateView>(g_bubble))
      ->Show();
}

// static
void PubkyIdentityBubbleView::Hide() {
  if (g_bubble && g_bubble->GetWidget()) {
    g_bubble->GetWidget()->Close();
  }
}

// static
bool PubkyIdentityBubbleView::IsShowing() {
  return g_bubble != nullptr;
}

// static
PubkyIdentityBubbleView* PubkyIdentityBubbleView::GetForTesting() {
  return g_bubble;
}

PubkyIdentityBubbleView::PubkyIdentityBubbleView(views::Button* anchor,
                                                 BrowserWindowInterface* browser)
    : BubbleDialogDelegateView(anchor, views::BubbleBorder::TOP_RIGHT),
      browser_(browser),
      service_(PubkySessionServiceFactory::GetForProfile(browser->GetProfile())) {
  SetButtons(static_cast<int>(ui::mojom::DialogButton::kNone));
  set_fixed_width(kBubbleWidth);
  set_margins(
      ChromeLayoutProvider::Get()->GetInsetsMetric(views::INSETS_DIALOG));
  auto* layout = SetLayoutManager(std::make_unique<views::BoxLayout>(
      views::BoxLayout::Orientation::kVertical, gfx::Insets(),
      ChromeLayoutProvider::Get()->GetDistanceMetric(
          views::DISTANCE_RELATED_CONTROL_VERTICAL)));
  layout->set_cross_axis_alignment(
      views::BoxLayout::CrossAxisAlignment::kStretch);
  observation_.Observe(service_.get());
  Rebuild();
}

PubkyIdentityBubbleView::~PubkyIdentityBubbleView() {
  if (g_bubble == this) {
    g_bubble = nullptr;
  }
}

void PubkyIdentityBubbleView::WindowClosing() {
  if (g_bubble == this) {
    g_bubble = nullptr;
  }
  BubbleDialogDelegateView::WindowClosing();
}

void PubkyIdentityBubbleView::OnPubkySessionChanged() {
  // A button in this panel may have caused the change; rebuild after its
  // click handler returns.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&PubkyIdentityBubbleView::Rebuild,
                                rebuild_weak_factory_.GetWeakPtr()));
}

void PubkyIdentityBubbleView::Rebuild() {
  RemoveAllChildViews();
  switch (service_->state()) {
    case State::kLoading:
      AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_LOADING),
                   views::style::STYLE_SECONDARY);
      break;
    case State::kSignedOut:
      if (browser_->GetProfile()->IsOffTheRecord()) {
        AddIncognitoContent();
      } else {
        AddSignedOutContent();
      }
      break;
    case State::kWaitingForApproval:
      AddSignInContent();
      break;
    case State::kSignedIn:
      AddSignedInContent();
      break;
    case State::kApprovalExpired:
      AddExpiredContent();
      break;
  }
  if (GetWidget()) {
    SizeToContents();
  }
}

views::View* PubkyIdentityBubbleView::AddParagraph(const std::u16string& text,
                                                   int text_style) {
  views::Label* label = AddChildView(MakeLabel(
      text, views::style::CONTEXT_DIALOG_BODY_TEXT, text_style));
  label->SetMultiLine(true);
  return label;
}

void PubkyIdentityBubbleView::AddSignInContent() {
  views::View* title = AddChildView(Row());
  title->AddChildView(std::make_unique<views::ImageView>(
      ui::ImageModel::FromResourceId(IDR_PRODUCT_LOGO_32)))
      ->SetImageSize(gfx::Size(kLogoSize, kLogoSize));
  title->AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_TITLE),
                views::style::CONTEXT_DIALOG_TITLE,
                views::style::STYLE_PRIMARY));

  AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_BODY),
               views::style::STYLE_PRIMARY);

  const std::string link = service_->signin_link();
  base::expected<gfx::ImageSkia, qr_code_generator::Error> qr_code =
      qr_code_generator::GenerateImage(
          base::as_byte_span(link), qr_code_generator::ModuleStyle::kSquares,
          qr_code_generator::LocatorStyle::kRounded,
          qr_code_generator::CenterImage::kProductLogo,
          qr_code_generator::QuietZone::kIncluded);
  if (qr_code.has_value()) {
    auto* image = AddChildView(std::make_unique<views::ImageView>(
        ui::ImageModel::FromImageSkia(*qr_code)));
    image->SetImageSize(gfx::Size(kQrCodeSize, kQrCodeSize));
    image->SetProperty(views::kElementIdentifierKey, kQrCodeElementId);
    image->GetViewAccessibility().SetName(l10n_util::GetStringUTF16(
        IDS_PUBKY_IDENTITY_SIGN_IN_QR_ACCESSIBLE_NAME));
  }

  AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_WAITING),
               views::style::STYLE_SECONDARY);
  AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_SCOPE),
               views::style::STYLE_SECONDARY);

  views::Label* separator = AddChildView(MakeLabel(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_OR),
      views::style::CONTEXT_DIALOG_BODY_TEXT, views::style::STYLE_SECONDARY));
  separator->SetHorizontalAlignment(gfx::ALIGN_CENTER);

  auto* passport = AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::OpenPassport,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_PASSPORT)));
  passport->SetProperty(views::kElementIdentifierKey, kPassportElementId);

  auto* get_ring = AddChildView(std::make_unique<views::Link>(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_GET_RING)));
  get_ring->SetCallback(
      base::BindRepeating(&PubkyIdentityBubbleView::OpenRingDownload,
                          base::Unretained(this)));
  get_ring->SetHorizontalAlignment(gfx::ALIGN_LEFT);

  AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::CancelSignIn,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_CANCEL)));
}

void PubkyIdentityBubbleView::AddSignedOutContent() {
  AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_TITLE),
                views::style::CONTEXT_DIALOG_TITLE,
                views::style::STYLE_PRIMARY));
  if (std::optional<int> error =
          ErrorMessageId(service_->last_sign_in_result())) {
    AddParagraph(l10n_util::GetStringUTF16(*error),
                 views::style::STYLE_PRIMARY);
  } else {
    AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_BODY),
                 views::style::STYLE_PRIMARY);
  }
  auto* again = AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::StartSignIn,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_IN_TRY_AGAIN)));
  again->SetStyle(ui::ButtonStyle::kProminent);
}

void PubkyIdentityBubbleView::AddIncognitoContent() {
  AddChildView(MakeLabel(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_INCOGNITO_TITLE),
      views::style::CONTEXT_DIALOG_TITLE, views::style::STYLE_PRIMARY));
  AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_INCOGNITO_BODY),
               views::style::STYLE_SECONDARY);
  auto* sign_in = AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::StartSignIn,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_INCOGNITO_SIGN_IN)));
  sign_in->SetStyle(ui::ButtonStyle::kProminent);
}

void PubkyIdentityBubbleView::AddIdentityHeader(int avatar_size) {
  const std::u16string label = PubkyIdentityLabel(*service_);
  views::View* header = AddChildView(Row());
  header->AddChildView(std::make_unique<views::ImageView>(
      PubkyIdentityAvatar(label, avatar_size)));
  views::View* text = header->AddChildView(Column());
  text->AddChildView(MakeLabel(label, views::style::CONTEXT_DIALOG_TITLE,
                               views::style::STYLE_PRIMARY));
  views::View* key_row = text->AddChildView(Row());
  if (std::optional<pubky_session::Key> user = service_->user()) {
    key_row->AddChildView(MakeLabel(ShortPubkyKey(*user),
                                    views::style::CONTEXT_DIALOG_BODY_TEXT,
                                    views::style::STYLE_SECONDARY));
  }
  std::unique_ptr<views::ImageButton> copy =
      views::CreateVectorImageButtonWithNativeTheme(
          base::BindRepeating(&PubkyIdentityBubbleView::CopyKey,
                              base::Unretained(this)),
          vector_icons::kContentCopyIcon, kCopyIconSize);
  copy->SetTooltipText(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_COPY_KEY));
  key_row->AddChildView(std::move(copy));
}

void PubkyIdentityBubbleView::AddSignedInContent() {
  AddIdentityHeader(/*avatar_size=*/48);
  if (std::optional<pubky_session::Key> homeserver = service_->homeserver()) {
    AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_HOMESERVER) +
                     u" " + ShortPubkyKey(*homeserver),
                 views::style::STYLE_SECONDARY);
  }
  if (!browser_->GetProfile()->IsOffTheRecord()) {
    AddChildView(std::make_unique<HoverButton>(
        base::BindRepeating(&PubkyIdentityBubbleView::OpenSettings,
                            base::Unretained(this)),
        l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_MANAGE_SITES)));
    AddChildView(std::make_unique<views::Separator>());
    AddIdentitiesSection();
  }
  AddChildView(std::make_unique<views::Separator>());
  auto* sign_out = AddChildView(std::make_unique<HoverButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::SignOut,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_OUT)));
  sign_out->SetProperty(views::kElementIdentifierKey, kSignOutElementId);
}

void PubkyIdentityBubbleView::AddIdentitiesSection() {
  AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_IDENTITIES),
                views::style::CONTEXT_DIALOG_BODY_TEXT,
                views::style::STYLE_SECONDARY));

  const std::u16string label = PubkyIdentityLabel(*service_);
  views::View* current = AddChildView(Row());
  current->AddChildView(std::make_unique<views::ImageView>(
      PubkyIdentityAvatar(label, kRowAvatarSize)));
  views::View* current_text = current->AddChildView(Column());
  current_text->AddChildView(MakeLabel(label,
                                       views::style::CONTEXT_DIALOG_BODY_TEXT,
                                       views::style::STYLE_PRIMARY));
  current_text->AddChildView(
      MakeLabel(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_THIS_WINDOW),
                views::style::CONTEXT_DIALOG_BODY_TEXT,
                views::style::STYLE_SECONDARY));

  const base::FilePath current_path = browser_->GetProfile()->GetPath();
  ProfileAttributesStorage& storage =
      g_browser_process->profile_manager()->GetProfileAttributesStorage();
  for (ProfileAttributesEntry* entry :
       storage.GetAllProfilesAttributesSortedForDisplay()) {
    if (entry->GetPath() == current_path) {
      continue;
    }
    AddChildView(std::make_unique<HoverButton>(
        base::BindRepeating(&PubkyIdentityBubbleView::SwitchToProfile,
                            base::Unretained(this), entry->GetPath()),
        std::make_unique<views::ImageView>(
            PubkyIdentityAvatar(entry->GetName(), kRowAvatarSize)),
        entry->GetName(),
        l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_OPENS_WINDOW)));
  }
  AddChildView(std::make_unique<HoverButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::AddIdentity,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_ADD)));
}

void PubkyIdentityBubbleView::AddExpiredContent() {
  views::Label* banner = AddChildView(MakeLabel(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_EXPIRED_TITLE),
      views::style::CONTEXT_DIALOG_BODY_TEXT, views::style::STYLE_PRIMARY));
  banner->SetBackground(
      views::CreateRoundedRectBackground(kAttentionBackground, 8));
  banner->SetBorder(views::CreateEmptyBorder(gfx::Insets::VH(8, 12)));

  AddIdentityHeader(/*avatar_size=*/40);
  AddParagraph(l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_EXPIRED_BODY),
               views::style::STYLE_SECONDARY);
  auto* approve = AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::StartSignIn,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_APPROVE_AGAIN)));
  approve->SetStyle(ui::ButtonStyle::kProminent);
  auto* sign_out = AddChildView(std::make_unique<views::MdTextButton>(
      base::BindRepeating(&PubkyIdentityBubbleView::SignOut,
                          base::Unretained(this)),
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_SIGN_OUT_SHORT)));
  sign_out->SetProperty(views::kElementIdentifierKey, kSignOutElementId);
}

void PubkyIdentityBubbleView::StartSignIn() {
  service_->StartSignIn(base::DoNothing());
}

void PubkyIdentityBubbleView::CancelSignIn() {
  service_->CancelSignIn();
}

void PubkyIdentityBubbleView::OpenPassport() {
  const std::string link = service_->signin_link();
  if (link.empty()) {
    return;
  }
  // Passport reads the link from the fragment, which stays out of server
  // logs, and delivers its approval to the same relay channel.
  chrome::AddSelectedTabWithURL(
      browser_,
      GURL(kPassportAuthorizeUrl + base::EscapeAllExceptUnreserved(link)),
      ui::PAGE_TRANSITION_LINK);
}

void PubkyIdentityBubbleView::OpenRingDownload() {
  chrome::AddSelectedTabWithURL(browser_, GURL(kRingDownloadUrl),
                                ui::PAGE_TRANSITION_LINK);
}

void PubkyIdentityBubbleView::CopyKey() {
  if (std::optional<pubky_session::Key> user = service_->user()) {
    ui::ScopedClipboardWriter(ui::ClipboardBuffer::kCopyPaste)
        .WriteText(base::UTF8ToUTF16(pubky_session::EncodeZ32(*user)));
  }
}

void PubkyIdentityBubbleView::SwitchToProfile(const base::FilePath& path) {
  profiles::SwitchToProfile(path, /*always_create=*/false);
  Hide();
}

void PubkyIdentityBubbleView::OpenSettings() {
  chrome::ShowSettingsSubPage(browser_.get(), "pubky");
  Hide();
}

void PubkyIdentityBubbleView::AddIdentity() {
  ProfileManager::CreateMultiProfileAsync(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_NEW_PROFILE_NAME),
      /*icon_index=*/0, /*is_hidden=*/false,
      base::BindOnce([](Profile* profile) {
        if (profile) {
          profiles::OpenBrowserWindowForProfile(
              base::DoNothing(), /*always_create=*/false,
              /*is_new_profile=*/true, /*open_command_line_urls=*/false,
              profile);
        }
      }));
  Hide();
}

void PubkyIdentityBubbleView::SignOut() {
  service_->SignOut();
}

BEGIN_METADATA(PubkyIdentityBubbleView)
END_METADATA

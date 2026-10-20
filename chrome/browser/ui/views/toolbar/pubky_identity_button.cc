// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_identity_button.h"

#include <optional>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_bubble_view.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/grit/theme_resources.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/views/accessibility/view_accessibility.h"

namespace {

using State = pubky_session::PubkySessionService::State;

constexpr int kIconSize = 20;

}  // namespace

PubkyIdentityButton::PubkyIdentityButton(Browser* browser)
    : ToolbarButton(base::BindRepeating(&PubkyIdentityButton::ButtonPressed,
                                        base::Unretained(this))),
      browser_(browser),
      service_(PubkySessionServiceFactory::GetForProfile(browser->profile())) {
  GetViewAccessibility().SetName(
      l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_ACCESSIBLE_NAME));
  if (!service_) {
    SetVisible(false);
    return;
  }
  observation_.Observe(service_.get());
  UpdateAppearance();
}

PubkyIdentityButton::~PubkyIdentityButton() = default;

void PubkyIdentityButton::OnPubkySessionChanged() {
  UpdateAppearance();
}

void PubkyIdentityButton::ButtonPressed() {
  if (PubkyIdentityBubbleView::IsShowing()) {
    PubkyIdentityBubbleView::Hide();
    return;
  }
  // Outside Incognito the panel shows a live sign-in link as soon as it
  // opens. Incognito asks first, because a sign-in there ends with the window.
  if (service_->state() == State::kSignedOut &&
      !browser_->profile()->IsOffTheRecord()) {
    service_->StartSignIn(base::DoNothing());
  }
  PubkyIdentityBubbleView::Show(this, browser_);
}

void PubkyIdentityButton::UpdateAppearance() {
  const bool incognito = browser_->profile()->IsOffTheRecord();
  ui::ImageModel icon = ui::ImageModel::FromResourceId(IDR_PRODUCT_LOGO_16);
  std::optional<SkColor> highlight;
  switch (service_->state()) {
    case State::kLoading:
      label_.clear();
      break;
    case State::kSignedOut:
      label_ = l10n_util::GetStringUTF16(
          incognito ? IDS_PUBKY_IDENTITY_BUTTON_INCOGNITO
                    : IDS_PUBKY_IDENTITY_BUTTON_SIGN_IN);
      if (!incognito) {
        highlight = kPubkyAccentColor;
      }
      break;
    case State::kWaitingForApproval:
      label_ = l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_WAITING);
      break;
    case State::kSignedIn:
      label_ = PubkyIdentityLabel(*service_);
      icon = PubkyIdentityAvatar(label_, kIconSize);
      break;
    case State::kApprovalExpired:
      label_ =
          l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_APPROVE_AGAIN);
      icon = PubkyIdentityAvatar(PubkyIdentityLabel(*service_), kIconSize);
      highlight = kPubkyAttentionColor;
      break;
  }
  SetImageModel(views::Button::STATE_NORMAL, icon);
  SetHighlight(label_, highlight);
  SetTooltipText(
      label_.empty()
          ? l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_ACCESSIBLE_NAME)
          : label_);
}

BEGIN_METADATA(PubkyIdentityButton)
END_METADATA

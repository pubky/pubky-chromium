// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUBBLE_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUBBLE_VIEW_H_

#include <string>

#include "base/files/file_path.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/scoped_observation.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/base/interaction/element_identifier.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/views/bubble/bubble_dialog_delegate_view.h"

class Browser;

namespace views {
class Button;
}  // namespace views

// The identity button's panel. Its content follows the session state: the
// sign-in link as a QR code with Passport as an alternative, the signed-in
// identity with the other identities and sign-out, the expired-approval
// prompt, and the Incognito explanation.
class PubkyIdentityBubbleView
    : public views::BubbleDialogDelegateView,
      public pubky_session::PubkySessionService::Observer {
  METADATA_HEADER(PubkyIdentityBubbleView, views::BubbleDialogDelegateView)

 public:
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kQrCodeElementId);
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kSignOutElementId);
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kPassportElementId);

  static void Show(views::Button* anchor, Browser* browser);
  static void Hide();
  static bool IsShowing();
  static PubkyIdentityBubbleView* GetForTesting();

  PubkyIdentityBubbleView(const PubkyIdentityBubbleView&) = delete;
  PubkyIdentityBubbleView& operator=(const PubkyIdentityBubbleView&) = delete;

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

 private:
  PubkyIdentityBubbleView(views::Button* anchor, Browser* browser);
  ~PubkyIdentityBubbleView() override;

  // views::WidgetDelegate:
  void WindowClosing() override;

  void Rebuild();
  void AddSignInContent();
  void AddSignedOutContent();
  void AddIncognitoContent();
  void AddSignedInContent();
  void AddExpiredContent();
  void AddIdentityHeader(int avatar_size);
  void AddIdentitiesSection();

  views::View* AddParagraph(const std::u16string& text,
                            int text_style);

  void StartSignIn();
  void CancelSignIn();
  void OpenPassport();
  void OpenRingDownload();
  void CopyKey();
  void SwitchToProfile(const base::FilePath& path);
  void AddIdentity();
  void SignOut();

  const raw_ptr<Browser> browser_;
  const raw_ptr<pubky_session::PubkySessionService> service_;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      observation_{this};
  base::WeakPtrFactory<PubkyIdentityBubbleView> rebuild_weak_factory_{this};
};

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUBBLE_VIEW_H_

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_identity_button.h"

#include <optional>
#include <string>

#include "base/logging.h"
#include "base/test/run_until.h"
#include "base/time/time.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_identity_text.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_window/public/browser_window_interface.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views/profiles/avatar_toolbar_button.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_bubble_view.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_util.h"
#include "chrome/browser/ui/views/toolbar/toolbar_view.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/pubky_session/session_store.h"
#include "content/public/test/browser_test.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/events/event.h"
#include "ui/events/event_utils.h"
#include "ui/views/test/button_test_api.h"
#include "ui/views/view_utils.h"

namespace {

using State = pubky_session::PubkySessionService::State;

class PubkyIdentityButtonBrowserTest : public InProcessBrowserTest {
 protected:
  ToolbarView* Toolbar(BrowserWindowInterface* browser) {
    return BrowserView::GetBrowserViewForBrowser(browser)->toolbar();
  }

  PubkyIdentityButton* Button(BrowserWindowInterface* browser) {
    return Toolbar(browser)->pubky_identity_button();
  }

  pubky_session::PubkySessionService* Service(BrowserWindowInterface* browser) {
    return PubkySessionServiceFactory::GetForProfile(browser->GetProfile());
  }

  void WaitUntilLoaded(BrowserWindowInterface* browser) {
    ASSERT_TRUE(base::test::RunUntil(
        [&] { return Service(browser)->state() != State::kLoading; }));
  }

  void Click(BrowserWindowInterface* browser) {
    views::test::ButtonTestApi(Button(browser))
        .NotifyClick(ui::MouseEvent(ui::EventType::kMousePressed, gfx::Point(),
                                    gfx::Point(), ui::EventTimeForNow(), 0, 0));
  }

  bool BubbleHas(ui::ElementIdentifier id) {
    PubkyIdentityBubbleView* bubble = PubkyIdentityBubbleView::GetForTesting();
    return bubble && bubble->GetViewByElementId(id);
  }

  pubky_session::StoredSession FakeSession() {
    pubky_session::StoredSession session;
    session.client_seed.fill(1);
    session.user.fill(2);
    session.homeserver.fill(3);
    session.grant_id = "AAAAAAAAAAAAAAAAAAAAAA";
    session.grant_jws = "header.payload.signature";
    session.capabilities = *pubky_session::ParseCapabilities("/pub/:rw");
    session.bearer = "bearer";
    const uint64_t now = static_cast<uint64_t>(base::Time::Now().ToTimeT());
    session.token_expires_at = now + 3600;
    session.grant_expires_at = now + 86400;
    return session;
  }
};

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       ReplacesTheAvatarButton) {
  ASSERT_TRUE(Button(browser()));
  EXPECT_TRUE(Button(browser())->GetVisible());
  for (views::View* child : Toolbar(browser())->children()) {
    if (views::IsViewClass<AvatarToolbarButton>(child)) {
      EXPECT_FALSE(child->GetVisible());
    }
  }
}

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       InvitesSignInWhenSignedOut) {
  WaitUntilLoaded(browser());
  EXPECT_EQ(Button(browser())->label_for_testing(),
            l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_SIGN_IN));
}

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       ClickStartsSignInAndShowsTheQrCode) {
  WaitUntilLoaded(browser());
  Click(browser());
  EXPECT_EQ(Service(browser())->state(), State::kWaitingForApproval);
  EXPECT_TRUE(PubkyIdentityBubbleView::IsShowing());
  EXPECT_EQ(Button(browser())->label_for_testing(),
            l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_WAITING));
  ASSERT_TRUE(base::test::RunUntil(
      [&] { return BubbleHas(PubkyIdentityBubbleView::kQrCodeElementId); }));
  EXPECT_TRUE(BubbleHas(PubkyIdentityBubbleView::kPassportElementId));

  Service(browser())->CancelSignIn();
  EXPECT_EQ(Service(browser())->state(), State::kSignedOut);
}

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       ShowsTheProfileNameWhenSignedIn) {
  WaitUntilLoaded(browser());
  Service(browser())->SignInForTesting(FakeSession(), "Marcos");
  EXPECT_EQ(Button(browser())->label_for_testing(), u"Marcos");

  Click(browser());
  EXPECT_EQ(Service(browser())->state(), State::kSignedIn);
  ASSERT_TRUE(base::test::RunUntil(
      [] { return PubkyIdentityBubbleView::GetForTesting() != nullptr; }));
  LOG(WARNING) << "identity panel children: "
               << PubkyIdentityBubbleView::GetForTesting()->children().size()
               << " state: " << static_cast<int>(Service(browser())->state());
  ASSERT_TRUE(base::test::RunUntil(
      [&] { return BubbleHas(PubkyIdentityBubbleView::kSignOutElementId); }));
}

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       ShowsTheShortKeyWithoutAProfileName) {
  WaitUntilLoaded(browser());
  pubky_session::StoredSession session = FakeSession();
  const pubky_session::Key user = session.user;
  Service(browser())->SignInForTesting(std::move(session), std::nullopt);
  EXPECT_EQ(Button(browser())->label_for_testing(), ShortPubkyKey(user));
}

IN_PROC_BROWSER_TEST_F(PubkyIdentityButtonBrowserTest,
                       IncognitoAsksBeforeSigningIn) {
  BrowserWindowInterface* incognito = CreateIncognitoBrowser();
  WaitUntilLoaded(incognito);
  EXPECT_EQ(Button(incognito)->label_for_testing(),
            l10n_util::GetStringUTF16(IDS_PUBKY_IDENTITY_BUTTON_INCOGNITO));
  Click(incognito);
  EXPECT_EQ(Service(incognito)->state(), State::kSignedOut);
  EXPECT_TRUE(PubkyIdentityBubbleView::IsShowing());
  // The regular profile's identity is separate.
  EXPECT_NE(Service(incognito), Service(browser()));
}

}  // namespace

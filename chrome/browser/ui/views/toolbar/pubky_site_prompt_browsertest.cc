// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_site_prompt_view.h"

#include <optional>
#include <string>
#include <vector>

#include "base/test/run_until.h"
#include "base/time/time.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views/location_bar/location_bar_view.h"
#include "chrome/browser/ui/views/location_bar/pubky_identity_chip_view.h"
#include "chrome/browser/ui/views/page_info/page_info_bubble_view_base.h"
#include "chrome/browser/ui/views/page_info/pubky_page_info_section.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/pubky_session/session_store.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "ui/events/event.h"
#include "ui/events/event_utils.h"
#include "ui/views/controls/button/button.h"
#include "ui/views/test/button_test_api.h"
#include "ui/views/widget/widget.h"
#include "url/origin.h"

namespace {

// Hosts that resolve without DNS: this fork's resolver ignores the test host
// rules, and CERT_OK covers both. They are distinct origins.
constexpr char kSite[] = "localhost";
constexpr char kOtherSite[] = "127.0.0.1";

using pubky_session::PubkySessionService;

pubky_session::Key FilledKey(uint8_t byte) {
  pubky_session::Key key;
  key.fill(byte);
  return key;
}

pubky_session::StoredSession FakeSession() {
  pubky_session::StoredSession session;
  session.client_seed = FilledKey(1);
  session.user = FilledKey(2);
  session.homeserver = FilledKey(3);
  session.grant_id = "AAAAAAAAAAAAAAAAAAAAAA";
  session.grant_jws = "header.payload.signature";
  session.capabilities = *pubky_session::ParseCapabilities("/pub/:rw");
  session.bearer = "bearer";
  const uint64_t now = static_cast<uint64_t>(base::Time::Now().ToTimeT());
  session.token_expires_at = now + 3600;
  session.grant_expires_at = now + 86400;
  return session;
}

void Click(views::Button* button) {
  views::test::ButtonTestApi(button).NotifyClick(
      ui::MouseEvent(ui::EventType::kMousePressed, gfx::Point(), gfx::Point(),
                     ui::EventTimeForNow(), 0, 0));
}

class PubkySitePromptBrowserTest : public InProcessBrowserTest {
 protected:
  void SetUpOnMainThread() override {
    host_resolver()->AddRule("*", "127.0.0.1");
    https_server_.SetSSLConfig(net::EmbeddedTestServer::CERT_OK);
    https_server_.ServeFilesFromSourceDirectory(GetChromeTestDataDir());
    ASSERT_TRUE(https_server_.Start());
    ASSERT_TRUE(base::test::RunUntil([&] {
      return Service()->state() != PubkySessionService::State::kLoading;
    }));
    Service()->SignInForTesting(FakeSession(), "Marcos");
  }

  PubkySessionService* Service() {
    return PubkySessionServiceFactory::GetForProfile(browser()->GetProfile());
  }

  HostContentSettingsMap* Settings() {
    return HostContentSettingsMapFactory::GetForProfile(browser()->GetProfile());
  }

  content::WebContents* Tab() {
    return browser()->tab_strip_model()->GetActiveWebContents();
  }

  GURL Url(std::string_view host) {
    return https_server_.GetURL(host, "/title1.html");
  }

  url::Origin Origin(std::string_view host) {
    return url::Origin::Create(Url(host));
  }

  std::vector<pubky_session::Capability> SiteScopes(std::string_view host) {
    return pubky_session::GetSiteScopes(Settings(), Origin(host),
                                        FilledKey(2));
  }

  void Allow(std::string_view host, std::string_view scopes) {
    pubky_session::AllowSiteScopes(Settings(), Origin(host), FilledKey(2),
                                   *pubky_session::ParseCapabilities(scopes));
  }

  // Starts requestSession() on the page; its outcome lands in window.result.
  void StartRequest(const std::string& scopes) {
    ASSERT_TRUE(content::ExecJs(
        Tab(), "window.result = navigator.pubky.requestSession(" + scopes +
                   ").then(s => s.publicKey, e => e.name);"));
  }

  std::string Result() {
    return content::EvalJs(Tab(), "window.result").ExtractString();
  }

  PubkySitePromptView* WaitForPrompt() {
    EXPECT_TRUE(base::test::RunUntil(
        [] { return PubkySitePromptView::GetForTesting() != nullptr; }));
    return PubkySitePromptView::GetForTesting();
  }

  void WaitForPromptToClose() {
    EXPECT_TRUE(base::test::RunUntil(
        [] { return PubkySitePromptView::GetForTesting() == nullptr; }));
  }

  PubkyIdentityChipView* Chip() {
    return BrowserView::GetBrowserViewForBrowser(browser())
        ->GetLocationBarView()
        ->pubky_identity_chip();
  }

  net::EmbeddedTestServer https_server_{net::EmbeddedTestServer::TYPE_HTTPS};
};

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, AllowIsRemembered) {
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/pub/a.test/:rw']");
  PubkySitePromptView* prompt = WaitForPrompt();
  ASSERT_TRUE(prompt);
  EXPECT_FALSE(prompt->is_ring_prompt_for_testing());
  prompt->AcceptDialog();
  EXPECT_EQ(Result(), pubky_session::EncodeZ32(FilledKey(2)));
  WaitForPromptToClose();
  EXPECT_EQ(SiteScopes(kSite),
            *pubky_session::ParseCapabilities("/pub/a.test/:rw"));

  // The answer holds for the site; a reload asks nothing.
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/pub/a.test/:r']");
  EXPECT_EQ(Result(), pubky_session::EncodeZ32(FilledKey(2)));
  EXPECT_FALSE(PubkySitePromptView::GetForTesting());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, DontAllowRejects) {
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/pub/a.test/:rw']");
  ASSERT_TRUE(WaitForPrompt());
  PubkySitePromptView::GetForTesting()->CancelDialog();
  EXPECT_EQ(Result(), "NotAllowedError");
  EXPECT_TRUE(SiteScopes(kSite).empty());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest,
                       EscalationAsksOnlyForTheDifference) {
  Allow(kSite, "/pub/a.test/:r");
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/pub/a.test/:r', '/pub/shared/:rw']");
  ASSERT_TRUE(WaitForPrompt());
  PubkySitePromptView::GetForTesting()->AcceptDialog();
  EXPECT_EQ(Result(), pubky_session::EncodeZ32(FilledKey(2)));
  EXPECT_EQ(SiteScopes(kSite),
            *pubky_session::ParseCapabilities("/pub/a.test/:r,/pub/shared/:rw"));
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, LeavingThePageCloses) {
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/pub/a.test/:rw']");
  ASSERT_TRUE(WaitForPrompt());
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kOtherSite)));
  WaitForPromptToClose();
  EXPECT_TRUE(SiteScopes(kSite).empty());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest,
                       PrivateScopesShowTheRingApproval) {
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  StartRequest("['/priv/a.test/:rw']");
  PubkySitePromptView* prompt = WaitForPrompt();
  ASSERT_TRUE(prompt);
  EXPECT_TRUE(prompt->is_ring_prompt_for_testing());
  EXPECT_TRUE(
      prompt->GetViewByElementId(PubkySitePromptView::kQrCodeElementId));
  EXPECT_FALSE(Service()->scope_approval_link().empty());

  // Cancel withdraws the Ring approval.
  prompt->CancelDialog();
  EXPECT_EQ(Result(), "NotAllowedError");
  EXPECT_TRUE(Service()->scope_approval_link().empty());
  EXPECT_TRUE(SiteScopes(kSite).empty());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest,
                       PageInfoDisconnectsTheSite) {
  Allow(kSite, "/pub/a.test/:rw");
  Allow(kOtherSite, "/pub/b.test/:rw");
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  BrowserView::GetBrowserViewForBrowser(browser())
      ->GetLocationBarView()
      ->ShowPageInfoDialog();
  views::BubbleDialogDelegateView* page_info =
      PageInfoBubbleViewBase::GetPageInfoBubbleForTesting();
  ASSERT_TRUE(page_info);
  views::View* section =
      page_info->GetViewByElementId(PubkyPageInfoSection::kSectionElementId);
  ASSERT_TRUE(section);
  EXPECT_TRUE(section->GetVisible());

  Click(static_cast<views::Button*>(page_info->GetViewByElementId(
      PubkyPageInfoSection::kDisconnectElementId)));
  EXPECT_TRUE(SiteScopes(kSite).empty());
  EXPECT_FALSE(section->GetVisible());
  // Other sites keep their access.
  EXPECT_FALSE(SiteScopes(kOtherSite).empty());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, PageInfoHidesWithoutAccess) {
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  BrowserView::GetBrowserViewForBrowser(browser())
      ->GetLocationBarView()
      ->ShowPageInfoDialog();
  views::BubbleDialogDelegateView* page_info =
      PageInfoBubbleViewBase::GetPageInfoBubbleForTesting();
  ASSERT_TRUE(page_info);
  views::View* section =
      page_info->GetViewByElementId(PubkyPageInfoSection::kSectionElementId);
  ASSERT_TRUE(section);
  EXPECT_FALSE(section->GetVisible());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, ChipFollowsTheSite) {
  Allow(kSite, "/pub/a.test/:rw");
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  EXPECT_TRUE(Chip()->GetVisible());
  EXPECT_EQ(Chip()->GetText(), u"Marcos");

  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kOtherSite)));
  EXPECT_FALSE(Chip()->GetVisible());

  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  EXPECT_TRUE(Chip()->GetVisible());
  pubky_session::RemoveSiteAccess(Settings(), Origin(kSite));
  EXPECT_FALSE(Chip()->GetVisible());
}

IN_PROC_BROWSER_TEST_F(PubkySitePromptBrowserTest, ChipHidesAfterSignOut) {
  Allow(kSite, "/pub/a.test/:rw");
  ASSERT_TRUE(ui_test_utils::NavigateToURL(browser(), Url(kSite)));
  ASSERT_TRUE(Chip()->GetVisible());
  Service()->SignOut();
  EXPECT_FALSE(Chip()->GetVisible());
}

}  // namespace

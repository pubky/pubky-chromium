// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/pubky_session/pubky_session_host_impl.h"

#include <memory>
#include <string>
#include <vector>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/test/run_until.h"
#include "base/time/time.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/pubky_session/session_store.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/url_loader_interceptor.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace {

// Hosts that resolve without DNS: this fork's resolver ignores the test host
// rules, and CERT_OK covers both. They are distinct origins.
constexpr char kSite[] = "localhost";
constexpr char kOtherSite[] = "127.0.0.1";

using pubky_session::Capability;
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

// The user's homeserver: one file and one directory under /pub/a.test/.
bool ServeHomeserver(const std::string& host,
                     content::URLLoaderInterceptor::RequestParams* params) {
  const GURL& url = params->url_request.url;
  if (url.host() != host) {
    return false;
  }
  const std::string prefix =
      "/storage/" + pubky_session::EncodeZ32(FilledKey(2)) + "/pub/a.test/";
  const std::string& method = params->url_request.method;
  if (method == "GET" && url.path() == prefix + "hello.txt") {
    content::URLLoaderInterceptor::WriteResponse(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n", "hello",
        params->client.get());
  } else if (method == "GET" && url.path() == prefix) {
    content::URLLoaderInterceptor::WriteResponse(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n",
        "pubky://u/pub/a.test/a\npubky://u/pub/a.test/b",
        params->client.get());
  } else if (method == "PUT" || method == "DELETE") {
    content::URLLoaderInterceptor::WriteResponse("HTTP/1.1 200 OK\n\n", "",
                                                 params->client.get());
  } else {
    content::URLLoaderInterceptor::WriteResponse("HTTP/1.1 404 Not Found\n\n",
                                                 "", params->client.get());
  }
  return true;
}

class PubkySessionHostBrowserTest : public InProcessBrowserTest,
                                    public PubkySessionHostImpl::Ui {
 protected:
  void SetUpOnMainThread() override {
    host_resolver()->AddRule("*", "127.0.0.1");
    https_server_.SetSSLConfig(net::EmbeddedTestServer::CERT_OK);
    https_server_.ServeFilesFromSourceDirectory(GetChromeTestDataDir());
    ASSERT_TRUE(https_server_.Start());
    interceptor_ = std::make_unique<content::URLLoaderInterceptor>(
        base::BindRepeating(&ServeHomeserver,
                            pubky_session::EncodeZ32(FilledKey(3))));
    PubkySessionHostImpl::SetUiForTesting(this);
    ASSERT_TRUE(base::test::RunUntil(
        [&] { return Service()->state() != PubkySessionService::State::kLoading; }));
  }

  void TearDownOnMainThread() override {
    PubkySessionHostImpl::SetUiForTesting(nullptr);
    interceptor_.reset();
  }

  // PubkySessionHostImpl::Ui:
  void OpenSignIn(content::WebContents* contents) override {
    ++open_sign_in_calls_;
  }
  void RequestAccess(content::WebContents* contents,
                     const url::Origin& origin,
                     const std::vector<Capability>& scopes,
                     base::OnceCallback<void(bool allowed)> callback) override {
    access_requests_.push_back(pubky_session::CapabilitiesToString(scopes));
    std::move(callback).Run(allow_);
  }
  void ShowScopeApproval(content::WebContents* contents,
                         const url::Origin& origin,
                         const std::vector<Capability>& scopes) override {
    scope_approvals_.push_back(pubky_session::CapabilitiesToString(scopes));
  }

  PubkySessionService* Service() {
    return PubkySessionServiceFactory::GetForProfile(browser()->GetProfile());
  }

  HostContentSettingsMap* Settings() {
    return HostContentSettingsMapFactory::GetForProfile(browser()->GetProfile());
  }

  content::WebContents* Tab() {
    return browser()->GetTabStripModel()->GetActiveWebContents();
  }

  url::Origin Origin(std::string_view host) {
    return url::Origin::Create(https_server_.GetURL(host, "/"));
  }

  std::string UserKey() { return pubky_session::EncodeZ32(FilledKey(2)); }

  void SignInAndOpen(std::string_view host) {
    Service()->SignInForTesting(FakeSession(), std::nullopt);
    ASSERT_TRUE(ui_test_utils::NavigateToURL(
        browser(), https_server_.GetURL(host, "/title1.html")));
  }

  void Allow(std::string_view host, std::string_view scopes) {
    pubky_session::AllowSiteScopes(
        Settings(), Origin(host), FilledKey(2),
        *pubky_session::ParseCapabilities(scopes));
  }

  // Runs `expression`, a promise, and returns its value as a string or the
  // name of the error it rejects with.
  std::string Call(const content::ToRenderFrameHost& target,
                   const std::string& expression) {
    const std::string result =
        content::EvalJs(target,
                        "(async () => { try { return 'ok|' + String(await (" +
                            expression +
                            ")); } catch (e) { return e.name + '|' + e.message + "
                            "' at ' + location.href + ' secure=' + "
                            "isSecureContext + ' page=' + "
                            "(document.body.innerText.match(/ERR_[A-Z_]+/) || "
                            "[document.body.innerText.slice(0, 80)])[0]; } })()")
            .ExtractString();
    const size_t bar = result.find('|');
    if (result.substr(0, bar) == "ok") {
      return result.substr(bar + 1);
    }
    // The error name is what tests compare; the rest helps when one fails.
    LOG(WARNING) << expression << " rejected: " << result;
    return result.substr(0, bar);
  }

  std::string RequestSession(const content::ToRenderFrameHost& target,
                             const std::string& scopes) {
    return Call(target, "navigator.pubky.requestSession(" + scopes +
                            ").then(s => (window.session = s).publicKey)");
  }

  net::EmbeddedTestServer https_server_{net::EmbeddedTestServer::TYPE_HTTPS};
  std::unique_ptr<content::URLLoaderInterceptor> interceptor_;
  bool allow_ = true;
  int open_sign_in_calls_ = 0;
  std::vector<std::string> access_requests_;
  std::vector<std::string> scope_approvals_;
};

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest,
                       AllowedScopesAreRememberedForTheSite) {
  SignInAndOpen(kSite);
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), UserKey());
  EXPECT_EQ(access_requests_, std::vector<std::string>({"/pub/a.test/:rw"}));
  EXPECT_EQ(pubky_session::GetSiteScopes(Settings(), Origin(kSite),
                                         FilledKey(2)),
            *pubky_session::ParseCapabilities("/pub/a.test/:rw"));

  // A covered request needs no prompt; a wider one asks for the difference.
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/notes/:r']"), UserKey());
  EXPECT_EQ(access_requests_.size(), 1u);
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/:r', '/pub/shared/:r']"),
            UserKey());
  EXPECT_EQ(access_requests_.back(), "/pub/shared/:r");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, ADeclinedRequestRejects) {
  allow_ = false;
  SignInAndOpen(kSite);
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), "NotAllowedError");
  EXPECT_TRUE(pubky_session::GetSiteScopes(Settings(), Origin(kSite),
                                           FilledKey(2))
                  .empty());
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, EnforcesTheSiteScopes) {
  Allow(kSite, "/pub/a.test/:r");
  SignInAndOpen(kSite);
  ASSERT_EQ(RequestSession(Tab(), "['/pub/a.test/:r']"), UserKey());
  EXPECT_TRUE(access_requests_.empty());

  EXPECT_EQ(Call(Tab(), "session.get('/pub/a.test/hello.txt')"
                        ".then(r => r.text())"),
            "hello");
  EXPECT_EQ(Call(Tab(), "session.list('/pub/a.test/').then(l => l.length)"),
            "2");
  EXPECT_EQ(Call(Tab(), "session.get('/pub/a.test/missing')"),
            "NotFoundError");
  // Outside the scope, or writing with read access only.
  EXPECT_EQ(Call(Tab(), "session.get('/pub/b.test/hello.txt')"),
            "NotAllowedError");
  EXPECT_EQ(Call(Tab(), "session.put('/pub/a.test/x', new Uint8Array([1]))"),
            "NotAllowedError");
  EXPECT_EQ(Call(Tab(), "session.delete('/pub/a.test/hello.txt')"),
            "NotAllowedError");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, WritesWithinTheScope) {
  Allow(kSite, "/pub/a.test/:rw");
  SignInAndOpen(kSite);
  ASSERT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), UserKey());
  EXPECT_EQ(Call(Tab(), "session.put('/pub/a.test/x', new Uint8Array([1]))"),
            "undefined");
  EXPECT_EQ(Call(Tab(), "session.delete('/pub/a.test/x')"), "undefined");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest,
                       RevocationTakesEffectOnTheNextCall) {
  Allow(kSite, "/pub/a.test/:rw");
  SignInAndOpen(kSite);
  ASSERT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), UserKey());
  ASSERT_EQ(Call(Tab(), "session.get('/pub/a.test/hello.txt')"
                        ".then(r => r.text())"),
            "hello");

  pubky_session::RemoveSiteAccess(Settings(), Origin(kSite));
  EXPECT_EQ(Call(Tab(), "session.get('/pub/a.test/hello.txt')"),
            "NotAllowedError");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, RejectsNonCanonicalPaths) {
  Allow(kSite, "/pub/a.test/:rw");
  SignInAndOpen(kSite);
  ASSERT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), UserKey());
  for (const char* call :
       {"session.get('/pub/a.test/../b.test/x')", "session.get('pub/a.test/x')",
        "session.get('/pub/a.test//x')", "session.get('/pub/a.test/./x')",
        "session.get('/pub/a.test/')", "session.list('/pub/a.test/x')",
        "session.put('/pub/a.test/x\\\\y', new Uint8Array())"}) {
    EXPECT_EQ(Call(Tab(), call), "TypeError") << call;
  }
  EXPECT_EQ(RequestSession(Tab(), "['/pub/../:rw']"), "TypeError");
  EXPECT_EQ(RequestSession(Tab(), "[]"), "TypeError");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, RefusesEncryptionKeys) {
  SignInAndOpen(kSite);
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/:rwe']"),
            "NotSupportedError");
  EXPECT_TRUE(access_requests_.empty());
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest, OnlySameOriginFrames) {
  Allow(kSite, "/pub/a.test/:r");
  Allow(kOtherSite, "/pub/b.test/:r");
  SignInAndOpen(kSite);
  ASSERT_TRUE(content::ExecJs(
      Tab(),
      "for (const id of ['same', 'cross']) {"
      "  const frame = document.createElement('iframe');"
      "  frame.id = id;"
      "  document.body.appendChild(frame);"
      "}"));
  ASSERT_TRUE(content::NavigateIframeToURL(
      Tab(), "same", https_server_.GetURL(kSite, "/title1.html")));
  ASSERT_TRUE(content::NavigateIframeToURL(
      Tab(), "cross", https_server_.GetURL(kOtherSite, "/title1.html")));

  content::RenderFrameHost* main_frame = Tab()->GetPrimaryMainFrame();
  EXPECT_EQ(RequestSession(content::ChildFrameAt(main_frame, 0),
                           "['/pub/a.test/:r']"),
            UserKey());
  EXPECT_EQ(RequestSession(content::ChildFrameAt(main_frame, 1),
                           "['/pub/b.test/:r']"),
            "NotAllowedError");
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest,
                       AccessBelongsToTheIdentityThatAllowedIt) {
  pubky_session::AllowSiteScopes(
      Settings(), Origin(kSite), FilledKey(9),
      *pubky_session::ParseCapabilities("/pub/a.test/:rw"));
  SignInAndOpen(kSite);
  EXPECT_EQ(RequestSession(Tab(), "['/pub/a.test/:rw']"), UserKey());
  EXPECT_EQ(access_requests_, std::vector<std::string>({"/pub/a.test/:rw"}));
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest,
                       ASignedOutRequestOpensSignInAndContinues) {
  ASSERT_EQ(Service()->state(), PubkySessionService::State::kSignedOut);
  ASSERT_TRUE(ui_test_utils::NavigateToURL(
      browser(), https_server_.GetURL(kSite, "/title1.html")));
  ASSERT_TRUE(content::ExecJs(
      Tab(),
      "window.result = navigator.pubky.requestSession(['/pub/a.test/:rw'])"
      "    .then(s => s.publicKey, e => e.name);"));
  ASSERT_TRUE(base::test::RunUntil([&] { return open_sign_in_calls_ == 1; }));

  Service()->SignInForTesting(FakeSession(), std::nullopt);
  EXPECT_EQ(content::EvalJs(Tab(), "window.result"), UserKey());
  EXPECT_EQ(access_requests_.size(), 1u);
}

IN_PROC_BROWSER_TEST_F(PubkySessionHostBrowserTest,
                       PrivateScopesWaitForARingApproval) {
  SignInAndOpen(kSite);
  ASSERT_TRUE(content::ExecJs(
      Tab(),
      "window.result = navigator.pubky.requestSession(['/priv/a.test/:rw'])"
      "    .then(s => s.publicKey, e => e.name);"));
  // Approving in Ring is the answer, so there is no separate prompt.
  ASSERT_TRUE(base::test::RunUntil(
      [&] { return !Service()->scope_approval_link().empty(); }));
  EXPECT_EQ(Service()->pending_scope_capabilities(),
            *pubky_session::ParseCapabilities("/priv/a.test/:rw"));
  EXPECT_EQ(scope_approvals_, std::vector<std::string>({"/priv/a.test/:rw"}));
  EXPECT_TRUE(access_requests_.empty());

  Service()->CancelSignIn();
  EXPECT_EQ(content::EvalJs(Tab(), "window.result"), "NotAllowedError");
  EXPECT_TRUE(pubky_session::GetSiteScopes(Settings(), Origin(kSite),
                                           FilledKey(2))
                  .empty());
}

}  // namespace

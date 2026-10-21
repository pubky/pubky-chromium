// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/settings/pubky_identity_handler.h"

#include <memory>
#include <string>

#include "base/files/file_path.h"
#include "base/test/bind.h"
#include "base/time/time.h"
#include "base/values.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/test/base/testing_profile.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/pubky_session/session_store.h"
#include "content/public/test/browser_task_environment.h"
#include "content/public/test/test_web_ui.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace settings {
namespace {

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

url::Origin Origin(const char* url) {
  return url::Origin::Create(GURL(url));
}

class TestPubkyIdentityHandler : public PubkyIdentityHandler {
 public:
  using PubkyIdentityHandler::PubkyIdentityHandler;
  using PubkyIdentityHandler::set_web_ui;
};

class PubkyIdentityHandlerTest : public testing::Test {
 protected:
  void SetUp() override {
    PubkySessionServiceFactory::GetInstance()->SetTestingFactory(
        &profile_,
        base::BindLambdaForTesting(
            [this](content::BrowserContext*) -> std::unique_ptr<KeyedService> {
              // In memory, with every request held by `factory_`.
              return std::make_unique<PubkySessionService>(
                  factory_.GetSafeWeakWrapper(),
                  factory_.GetSafeWeakWrapper(),
                  /*os_crypt_async=*/nullptr, base::FilePath());
            }));
    handler_ = std::make_unique<TestPubkyIdentityHandler>(&profile_);
    handler_->set_web_ui(&web_ui_);
    handler_->RegisterMessages();
    handler_->AllowJavascriptForTesting();
  }

  void TearDown() override { handler_.reset(); }

  PubkySessionService* Service() {
    return PubkySessionServiceFactory::GetForProfile(&profile_);
  }

  HostContentSettingsMap* Settings() {
    return HostContentSettingsMapFactory::GetForProfile(&profile_);
  }

  void Allow(const char* url, const pubky_session::Key& user) {
    pubky_session::AllowSiteScopes(
        Settings(), Origin(url), user,
        *pubky_session::ParseCapabilities("/pub/site/:rw"));
  }

  bool SentIdentityUpdate() {
    for (const auto& call : web_ui_.call_data()) {
      if (call->function_name() == "cr.webUIListenerCallback" &&
          call->arg1()->GetString() == "pubky-identity-changed") {
        return true;
      }
    }
    return false;
  }

  content::BrowserTaskEnvironment environment_;
  TestingProfile profile_;
  network::TestURLLoaderFactory factory_;
  content::TestWebUI web_ui_;
  std::unique_ptr<TestPubkyIdentityHandler> handler_;
};

TEST_F(PubkyIdentityHandlerTest, ReportsSignedOut) {
  base::DictValue identity = handler_->GetIdentityForTesting();
  EXPECT_EQ(identity.FindBool("available"), true);
  EXPECT_EQ(identity.FindBool("signedIn"), false);
  EXPECT_FALSE(identity.FindList("sites"));
}

TEST_F(PubkyIdentityHandlerTest, ListsTheSitesOfThisIdentity) {
  Service()->SignInForTesting(FakeSession(), "Marcos");
  Allow("https://a.test", FilledKey(2));
  Allow("https://b.test", FilledKey(2));
  // Allowed for another identity, so not listed.
  Allow("https://c.test", FilledKey(9));

  base::DictValue identity = handler_->GetIdentityForTesting();
  EXPECT_EQ(identity.FindBool("signedIn"), true);
  EXPECT_EQ(*identity.FindString("name"), "Marcos");
  EXPECT_EQ(*identity.FindString("publicKey"),
            pubky_session::EncodeZ32(FilledKey(2)));
  EXPECT_NE(identity.FindString("approval")->find("/pub/"), std::string::npos);
  const base::ListValue* sites = identity.FindList("sites");
  ASSERT_TRUE(sites);
  ASSERT_EQ(sites->size(), 2u);
  for (const base::Value& site : *sites) {
    const std::string* origin = site.GetDict().FindString("origin");
    EXPECT_TRUE(*origin == "https://a.test" || *origin == "https://b.test");
    EXPECT_EQ(*site.GetDict().FindString("access"),
              "Read and write /pub/site/");
  }
}

TEST_F(PubkyIdentityHandlerTest, ResolvesTheIdentityForThePage) {
  Service()->SignInForTesting(FakeSession(), "Marcos");
  web_ui_.HandleReceivedMessage("getPubkyIdentity",
                                base::ListValue().Append("callback-1"));
  const content::TestWebUI::CallData& call = *web_ui_.call_data().back();
  EXPECT_EQ(call.function_name(), "cr.webUIResponse");
  EXPECT_EQ(call.arg1()->GetString(), "callback-1");
  EXPECT_TRUE(call.arg2()->GetBool());
  EXPECT_EQ(*call.arg3()->GetDict().FindString("name"), "Marcos");
}

TEST_F(PubkyIdentityHandlerTest, RemovesOneSite) {
  Service()->SignInForTesting(FakeSession(), "Marcos");
  Allow("https://a.test", FilledKey(2));
  Allow("https://b.test", FilledKey(2));
  web_ui_.ClearTrackedCalls();

  web_ui_.HandleReceivedMessage("removePubkySite",
                                base::ListValue().Append("https://a.test"));
  EXPECT_TRUE(pubky_session::GetSiteScopes(Settings(), Origin("https://a.test"),
                                           FilledKey(2))
                  .empty());
  EXPECT_FALSE(pubky_session::GetSiteScopes(
                   Settings(), Origin("https://b.test"), FilledKey(2))
                   .empty());
  EXPECT_TRUE(SentIdentityUpdate());
}

TEST_F(PubkyIdentityHandlerTest, SignsOutAndRevokes) {
  Service()->SignInForTesting(FakeSession(), "Marcos");
  web_ui_.ClearTrackedCalls();

  web_ui_.HandleReceivedMessage("signOutPubky", base::ListValue());
  EXPECT_EQ(Service()->state(), PubkySessionService::State::kSignedOut);
  // The grant's revocation went to the homeserver.
  EXPECT_EQ(factory_.NumPending(), 1);
  EXPECT_TRUE(SentIdentityUpdate());
  EXPECT_EQ(handler_->GetIdentityForTesting().FindBool("signedIn"), false);
}

}  // namespace
}  // namespace settings

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/pubky_session_service.h"

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "components/os_crypt/async/browser/os_crypt_async.h"
#include "components/os_crypt/async/browser/test_utils.h"
#include "components/pubky_session/core/grant_session.h"
#include "components/pubky_session/core/jws.h"
#include "components/pubky_session/core/pkarr_packet.h"
#include "net/http/http_status_code.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/test/test_url_loader_factory.h"
#include "services/network/test/test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

using Result = PubkySessionService::SignInResult;
using State = PubkySessionService::State;

constexpr char kRelayInbox[] = "https://relay.test/inbox";
constexpr char kPkarrA[] = "https://pkarr-a.test";
constexpr char kPkarrB[] = "https://pkarr-b.test";
constexpr char kGrantId[] = "AAAAAAAAAAAAAAAAAAAAAA";

Key Seed(uint8_t byte) {
  Key key;
  key.fill(byte);
  return key;
}

uint64_t Now() {
  return static_cast<uint64_t>(base::Time::Now().ToTimeT());
}

struct CapturedRequest {
  std::string method;
  GURL url;
  std::string body;
};

class PubkySessionServiceTest : public testing::Test {
 protected:
  PubkySessionServiceTest()
      : user_seed_(Seed(7)),
        user_(Ed25519PublicKey(user_seed_)),
        homeserver_(Ed25519PublicKey(Seed(3))) {}

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    os_crypt_ = os_crypt_async::GetTestOSCryptAsyncForTesting(
        /*is_sync_for_unittests=*/true);
    factory_.SetInterceptor(base::BindRepeating(
        [](std::vector<CapturedRequest>* requests,
           const network::ResourceRequest& request) {
          requests->push_back(
              {request.method, request.url, network::GetUploadData(request)});
        },
        &requests_));
    shutdown_factory_.SetInterceptor(base::BindRepeating(
        [](std::vector<CapturedRequest>* requests,
           const network::ResourceRequest& request) {
          requests->push_back(
              {request.method, request.url, network::GetUploadData(request)});
        },
        &shutdown_requests_));
  }

  base::FilePath StoragePath() const {
    return temp_dir_.GetPath().AppendASCII(kStorageFileName);
  }

  std::unique_ptr<PubkySessionService> CreateService(bool persistent = true) {
    PubkySessionService::Config config;
    config.relay_inbox = kRelayInbox;
    config.pkarr_relays = {kPkarrA, kPkarrB};
    auto service = std::make_unique<PubkySessionService>(
        factory_.GetSafeWeakWrapper(), shutdown_factory_.GetSafeWeakWrapper(),
        os_crypt_.get(), persistent ? StoragePath() : base::FilePath(),
        config);
    task_environment_.RunUntilIdle();
    return service;
  }

  std::string ProfileUrl() const {
    return GURL("https://" + EncodeZ32(homeserver_) + "/storage/" +
                EncodeZ32(user_) + "/pub/pubky.app/profile.json")
        .spec();
  }

  std::string SessionUrl() const {
    return GURL("https://" + EncodeZ32(homeserver_) + kGrantSessionPath)
        .spec();
  }

  std::string GrantJws(const Key& client_key,
                       std::string_view capabilities = R"(["/pub/:rw"])") {
    return SignJws(
        kGrantJwsType,
        base::StrCat({R"({"caps":)", capabilities,
                      R"(,"client_id":"pubky-browser","cnf":")",
                      EncodeZ32(client_key), R"(","exp":)",
                      base::NumberToString(Now() + 86400), R"(,"iat":)",
                      base::NumberToString(Now()), R"(,"iss":")",
                      EncodeZ32(user_), R"(","jti":")", kGrantId, R"("})"}),
        user_seed_);
  }

  // Ring approving the pending request.
  void ServeApproval(PubkySessionService& service,
                     std::optional<Key> client_key = std::nullopt) {
    const SigninGrantRequest* request = service.pending_request_for_testing();
    ASSERT_TRUE(request);
    factory_.AddResponse(
        RelayChannelUrl(*request),
        SealSecretBoxForTesting(
            GrantJws(client_key.value_or(request->client_public_key)),
            request->channel_key));
  }

  void ServePkarr(const char* relay = kPkarrA) {
    factory_.AddResponse(
        base::StrCat({relay, "/", EncodeZ32(user_)}),
        SignRelayPayloadForTesting(
            user_seed_, 1, BuildPubkyRecordPacketForTesting(user_, homeserver_)));
  }

  void ServeSession(const std::string& token,
                    uint64_t token_expires_at,
                    uint64_t grant_expires_at) {
    factory_.AddResponse(
        SessionUrl(),
        base::StrCat(
            {R"({"token":")", token, R"(","session":{"homeserver":")",
             EncodeZ32(homeserver_), R"(","pubky":")", EncodeZ32(user_),
             R"(","client_id":"pubky-browser","capabilities":["/pub/:rw"],)",
             R"("grant_id":")", kGrantId, R"(","token_expires_at":)",
             base::NumberToString(token_expires_at), R"(,"grant_expires_at":)",
             base::NumberToString(grant_expires_at), R"(,"created_at":1}})"}));
  }

  Result SignIn(PubkySessionService& service,
                uint64_t token_lifetime = 3600,
                uint64_t grant_lifetime = 86400) {
    base::test::TestFuture<Result> result;
    service.StartSignIn(result.GetCallback());
    ServeApproval(service);
    ServePkarr();
    ServeSession("bearer-1", Now() + token_lifetime, Now() + grant_lifetime);
    return result.Get();
  }

  std::optional<std::string> Bearer(PubkySessionService& service) {
    base::test::TestFuture<std::optional<std::string>> bearer;
    service.GetBearer(bearer.GetCallback());
    return bearer.Get();
  }

  bool SawRequest(const std::vector<CapturedRequest>& requests,
                  std::string_view method,
                  const std::string& url) const {
    for (const CapturedRequest& request : requests) {
      if (request.method == method && request.url.spec() == url) {
        return true;
      }
    }
    return false;
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<os_crypt_async::OSCryptAsync> os_crypt_;
  network::TestURLLoaderFactory factory_;
  network::TestURLLoaderFactory shutdown_factory_;
  std::vector<CapturedRequest> requests_;
  std::vector<CapturedRequest> shutdown_requests_;
  const Key user_seed_;
  const Key user_;
  const Key homeserver_;
};

TEST_F(PubkySessionServiceTest, StartsSignedOut) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  EXPECT_EQ(service->state(), State::kSignedOut);
  EXPECT_FALSE(service->user());
  EXPECT_EQ(Bearer(*service), std::nullopt);
}

TEST_F(PubkySessionServiceTest, SignsInThroughRelayPkarrAndHomeserver) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  EXPECT_EQ(service->state(), State::kWaitingForApproval);
  EXPECT_TRUE(service->signin_link().starts_with(
      "pubkyauth://signin_grant?caps=%2Fpub%2F%3Arw&relay="));

  ServeApproval(*service);
  ServePkarr();
  ServeSession("bearer-1", Now() + 3600, Now() + 86400);
  EXPECT_EQ(result.Get(), Result::kSignedIn);

  EXPECT_EQ(service->state(), State::kSignedIn);
  EXPECT_EQ(service->user(), user_);
  EXPECT_EQ(service->homeserver(), homeserver_);
  EXPECT_EQ(service->capabilities(), *ParseCapabilities("/pub/:rw"));
  EXPECT_TRUE(service->signin_link().empty());
  EXPECT_EQ(Bearer(*service), "bearer-1");
  EXPECT_FALSE(service->pending_request_for_testing());
  EXPECT_EQ(service->last_sign_in_result(), Result::kSignedIn);
  // The grant was exchanged at the homeserver from the user's record.
  EXPECT_TRUE(SawRequest(requests_, "POST", SessionUrl()));
}

TEST_F(PubkySessionServiceTest, ReadsTheDisplayNameFromTheOwnProfile) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  factory_.AddResponse(ProfileUrl(),
                       "{\"name\":\"  Marcos\\u0007 \",\"bio\":\"hi\"}");
  ASSERT_EQ(SignIn(*service), Result::kSignedIn);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(service->display_name(), "Marcos");

  service->SignOut();
  EXPECT_FALSE(service->display_name());
}

TEST_F(PubkySessionServiceTest, KeepsNoDisplayNameWithoutAProfile) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  factory_.AddResponse(ProfileUrl(), "", net::HTTP_NOT_FOUND);
  ASSERT_EQ(SignIn(*service), Result::kSignedIn);
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(service->display_name());
}

TEST_F(PubkySessionServiceTest, PersistsEncryptedAndRestores) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  ASSERT_EQ(SignIn(*service), Result::kSignedIn);
  task_environment_.RunUntilIdle();

  std::string stored;
  ASSERT_TRUE(base::ReadFileToString(StoragePath(), &stored));
  EXPECT_EQ(stored.find("bearer-1"), std::string::npos);
  EXPECT_EQ(stored.find(EncodeZ32(user_)), std::string::npos);

  service->Shutdown();
  service.reset();
  service = CreateService();
  EXPECT_EQ(service->state(), State::kSignedIn);
  EXPECT_EQ(service->user(), user_);
  EXPECT_EQ(Bearer(*service), "bearer-1");
}

TEST_F(PubkySessionServiceTest, PollsAgainWhenTheRelayHasNothingYet) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  task_environment_.FastForwardBy(base::Seconds(31));
  EXPECT_EQ(service->state(), State::kWaitingForApproval);
  EXPECT_EQ(factory_.NumPending(), 1);

  ServeApproval(*service);
  ServePkarr();
  ServeSession("bearer-1", Now() + 3600, Now() + 86400);
  EXPECT_EQ(result.Get(), Result::kSignedIn);
}

TEST_F(PubkySessionServiceTest, SignInTimesOut) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  task_environment_.FastForwardBy(base::Minutes(6));
  EXPECT_EQ(result.Get(), Result::kTimedOut);
  EXPECT_EQ(service->state(), State::kSignedOut);
}

TEST_F(PubkySessionServiceTest, CancelsSignIn) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  service->CancelSignIn();
  EXPECT_EQ(result.Get(), Result::kCancelled);
  EXPECT_EQ(service->state(), State::kSignedOut);
}

TEST_F(PubkySessionServiceTest, RejectsAnApprovalForAnotherClient) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  ServeApproval(*service, Ed25519PublicKey(Seed(9)));
  EXPECT_EQ(result.Get(), Result::kRejected);
  EXPECT_EQ(service->state(), State::kSignedOut);
  EXPECT_EQ(service->last_sign_in_result(), Result::kRejected);
}

TEST_F(PubkySessionServiceTest, FallsBackToTheSecondPkarrRelay) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  ServeApproval(*service);
  factory_.AddResponse(base::StrCat({kPkarrA, "/", EncodeZ32(user_)}), "",
                       net::HTTP_NOT_FOUND);
  ServePkarr(kPkarrB);
  ServeSession("bearer-1", Now() + 3600, Now() + 86400);
  EXPECT_EQ(result.Get(), Result::kSignedIn);
}

TEST_F(PubkySessionServiceTest, FailsWithoutAHomeserverRecord) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  ServeApproval(*service);
  for (const char* relay : {kPkarrA, kPkarrB}) {
    factory_.AddResponse(base::StrCat({relay, "/", EncodeZ32(user_)}), "",
                         net::HTTP_NOT_FOUND);
  }
  EXPECT_EQ(result.Get(), Result::kHomeserverNotFound);
}

TEST_F(PubkySessionServiceTest, IgnoresAHomeserverRecordSignedByAnotherKey) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  ServeApproval(*service);
  for (const char* relay : {kPkarrA, kPkarrB}) {
    factory_.AddResponse(
        base::StrCat({relay, "/", EncodeZ32(user_)}),
        SignRelayPayloadForTesting(
            Seed(9), 1, BuildPubkyRecordPacketForTesting(user_, homeserver_)));
  }
  EXPECT_EQ(result.Get(), Result::kHomeserverNotFound);
}

TEST_F(PubkySessionServiceTest, FailsWhenTheHomeserverRefusesTheGrant) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  base::test::TestFuture<Result> result;
  service->StartSignIn(result.GetCallback());
  ServeApproval(*service);
  ServePkarr();
  factory_.AddResponse(SessionUrl(), "", net::HTTP_FORBIDDEN);
  EXPECT_EQ(result.Get(), Result::kExchangeFailed);
  EXPECT_EQ(service->state(), State::kSignedOut);
}

TEST_F(PubkySessionServiceTest, RefreshesTheBearerBeforeItExpires) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  ASSERT_EQ(SignIn(*service, /*token_lifetime=*/120), Result::kSignedIn);
  ServeSession("bearer-2", Now() + 3600, Now() + 86400);
  task_environment_.FastForwardBy(base::Seconds(61));
  EXPECT_EQ(Bearer(*service), "bearer-2");
}

TEST_F(PubkySessionServiceTest, ARejectedRefreshExpiresTheApproval) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  ASSERT_EQ(SignIn(*service, /*token_lifetime=*/120), Result::kSignedIn);
  factory_.AddResponse(SessionUrl(), "", net::HTTP_UNAUTHORIZED);
  task_environment_.FastForwardBy(base::Seconds(61));
  EXPECT_EQ(service->state(), State::kApprovalExpired);
  EXPECT_EQ(service->user(), user_);
  EXPECT_EQ(Bearer(*service), std::nullopt);

  // Approving again replaces the expired grant.
  EXPECT_EQ(SignIn(*service), Result::kSignedIn);
  EXPECT_EQ(service->state(), State::kSignedIn);
}

TEST_F(PubkySessionServiceTest, SignOutRevokesAndForgets) {
  std::unique_ptr<PubkySessionService> service = CreateService();
  ASSERT_EQ(SignIn(*service), Result::kSignedIn);
  task_environment_.RunUntilIdle();
  ASSERT_TRUE(base::PathExists(StoragePath()));

  service->SignOut();
  task_environment_.RunUntilIdle();
  EXPECT_EQ(service->state(), State::kSignedOut);
  EXPECT_FALSE(service->user());
  EXPECT_FALSE(base::PathExists(StoragePath()));
  bool revoked = false;
  for (const CapturedRequest& request : requests_) {
    if (request.method == "DELETE" && request.url.spec() == SessionUrl()) {
      revoked = request.body.find("\"grant\"") != std::string::npos &&
                request.body.find("\"pop\"") != std::string::npos;
    }
  }
  EXPECT_TRUE(revoked);
}

TEST_F(PubkySessionServiceTest, IncognitoKeepsNothingOnDiskAndRevokesAtEnd) {
  std::unique_ptr<PubkySessionService> service =
      CreateService(/*persistent=*/false);
  ASSERT_EQ(SignIn(*service), Result::kSignedIn);
  task_environment_.RunUntilIdle();
  EXPECT_TRUE(base::IsDirectoryEmpty(temp_dir_.GetPath()));

  service->Shutdown();
  EXPECT_TRUE(SawRequest(shutdown_requests_, "DELETE", SessionUrl()));
}

}  // namespace
}  // namespace pubky_session

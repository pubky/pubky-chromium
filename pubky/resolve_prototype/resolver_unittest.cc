// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pubky/resolve_prototype/resolver.h"

#include <memory>
#include <string>
#include <utility>

#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/threading/platform_thread.h"
#include "net/base/net_errors.h"
#include "net/http/http_status_code.h"
#include "pubky/resolve_prototype/signed_bundle_fixture.rs.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/weak_wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "services/network/test/test_url_loader_factory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky::prototype {
namespace {

constexpr char kEndpoint[] = "https://resolver.example/v1/resolve";
constexpr char kService[] =
    "4msqbgpkfcdgnzrrsyp5hgno8rfa4sx15c79ughsq95ikycunowy";

class ResolverTest : public testing::Test {
 protected:
  const std::vector<pkresolve::HttpProtocol> kProtocols = {
      pkresolve::HttpProtocol::Http2, pkresolve::HttpProtocol::Http11};
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  network::TestURLLoaderFactory factory_;
  Resolver resolver_{factory_.GetSafeWeakWrapper(), GURL(kEndpoint)};
};

TEST_F(ResolverTest, UsesPkarrDevByDefault) {
  Resolver resolver(factory_.GetSafeWeakWrapper());
  base::test::TestFuture<ResolveResult> future;
  resolver.Resolve(kService, 443, kProtocols, future.GetCallback());
  const network::ResourceRequest* request = nullptr;
  ASSERT_TRUE(factory_.IsPending("https://pkarr.dev/v1/resolve", &request));
  ASSERT_TRUE(request);
  EXPECT_EQ(request->method, "POST");
  EXPECT_EQ(request->credentials_mode, network::mojom::CredentialsMode::kOmit);
  resolver.Cancel();
}

TEST_F(ResolverTest, InvalidServiceDoesNotFetch) {
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve("example.com", 443, kProtocols, future.GetCallback());
  const auto& result = future.Get();
  ASSERT_TRUE(result.response);
  EXPECT_EQ(result.response->status.code, pkresolve::StatusCode::InvalidInput);
  EXPECT_TRUE(factory_.pending_requests()->empty());
}

TEST_F(ResolverTest, RejectsCleartextEndpoint) {
  Resolver resolver(factory_.GetSafeWeakWrapper(),
                    GURL("http://resolver.example/v1/resolve"));
  base::test::TestFuture<ResolveResult> future;
  resolver.Resolve(kService, 443, kProtocols, future.GetCallback());
  EXPECT_EQ(future.Get().net_error, net::ERR_INVALID_ARGUMENT);
  EXPECT_TRUE(factory_.pending_requests()->empty());
}

TEST_F(ResolverTest, FetchOmitsCredentialsAndRejectsRedirects) {
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(kService, 443, kProtocols, future.GetCallback());
  const network::ResourceRequest* request = nullptr;
  ASSERT_TRUE(factory_.IsPending(kEndpoint, &request));
  ASSERT_TRUE(request);
  EXPECT_EQ(request->method, "POST");
  EXPECT_EQ(request->credentials_mode, network::mojom::CredentialsMode::kOmit);
  EXPECT_EQ(request->redirect_mode, network::mojom::RedirectMode::kError);
  resolver_.Cancel();
}

TEST_F(ResolverTest, InvalidBundleIsProtocolFailure) {
  factory_.AddResponse(kEndpoint, R"({"schema":1,"packets":[]})");
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(kService, 443, kProtocols, future.GetCallback());
  const auto& result = future.Get();
  EXPECT_EQ(result.net_error, net::OK);
  ASSERT_TRUE(result.response);
  EXPECT_EQ(result.response->status.code, pkresolve::StatusCode::InvalidBundle);
  EXPECT_TRUE(result.expires_at.is_null());
}

TEST_F(ResolverTest, HttpErrorIsTransportFailure) {
  factory_.AddResponse(kEndpoint, "unavailable", net::HTTP_SERVICE_UNAVAILABLE);
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(kService, 443, kProtocols, future.GetCallback());
  const auto& result = future.Get();
  EXPECT_EQ(result.net_error, net::ERR_HTTP_RESPONSE_CODE_FAILURE);
  EXPECT_FALSE(result.response);
}

TEST_F(ResolverTest, OversizedResponseFailsBeforeRustParsing) {
  factory_.AddResponse(kEndpoint, std::string(1024 * 1024 + 1, 'x'));
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(kService, 443, kProtocols, future.GetCallback());
  const auto& result = future.Get();
  EXPECT_EQ(result.net_error, net::ERR_INSUFFICIENT_RESOURCES);
  EXPECT_FALSE(result.response);
}

TEST_F(ResolverTest, TimeoutCompletesLookup) {
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(kService, 443, kProtocols, future.GetCallback());
  task_environment_.FastForwardBy(base::Seconds(11));
  EXPECT_EQ(future.Get().net_error, net::ERR_TIMED_OUT);
}

TEST_F(ResolverTest, CancelSuppressesDeliveryAndAllowsNextLookup) {
  base::test::TestFuture<ResolveResult> canceled;
  resolver_.Resolve(kService, 443, kProtocols, canceled.GetCallback());
  resolver_.Cancel();
  factory_.AddResponse(kEndpoint, "invalid JSON");
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(canceled.IsReady());

  base::test::TestFuture<ResolveResult> next;
  resolver_.Resolve(kService, 443, kProtocols, next.GetCallback());
  ASSERT_TRUE(next.Get().response);
  EXPECT_EQ(next.Get().response->status.code,
            pkresolve::StatusCode::InvalidBundle);
}

TEST_F(ResolverTest, SecondLookupDoesNotReplaceActiveRequest) {
  base::test::TestFuture<ResolveResult> first;
  resolver_.Resolve(kService, 443, kProtocols, first.GetCallback());
  base::test::TestFuture<ResolveResult> second;
  resolver_.Resolve(kService, 443, kProtocols, second.GetCallback());
  EXPECT_EQ(second.Get().net_error, net::ERR_UNEXPECTED);
  EXPECT_FALSE(first.IsReady());
  factory_.AddResponse(kEndpoint, "invalid JSON");
  ASSERT_TRUE(first.Get().response);
}

TEST_F(ResolverTest, DestructionSuppressesDelivery) {
  base::test::TestFuture<ResolveResult> future;
  {
    Resolver resolver(factory_.GetSafeWeakWrapper(), GURL(kEndpoint));
    resolver.Resolve(kService, 443, kProtocols, future.GetCallback());
  }
  factory_.AddResponse(kEndpoint, "invalid JSON");
  task_environment_.RunUntilIdle();
  EXPECT_FALSE(future.IsReady());
}

TEST_F(ResolverTest, TamperedSignatureIsRejectedWithoutCaching) {
  const auto fixture = test::make_tampered_bundle();
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  base::test::TestFuture<ResolveResult> rejected;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    rejected.GetCallback());
  ASSERT_EQ(rejected.Get().net_error, net::OK);
  ASSERT_TRUE(rejected.Get().response);
  EXPECT_EQ(rejected.Get().response->status.code,
            pkresolve::StatusCode::InvalidBundle);

  factory_.ClearResponses();
  base::test::TestFuture<ResolveResult> retry;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    retry.GetCallback());
  EXPECT_FALSE(retry.IsReady());
  EXPECT_EQ(factory_.total_requests(), 2u);
  const auto valid = test::make_signed_bundle(60, 10);
  ASSERT_TRUE(factory_.SimulateResponseForPendingRequest(
      kEndpoint, std::string(valid.bundle)));
  ASSERT_TRUE(retry.Get().response);
  EXPECT_EQ(retry.Get().response->status.code, pkresolve::StatusCode::Ok);
}

TEST_F(ResolverTest, SignedBundleResolvesEndpointAndPreservesFreshness) {
  const auto fixture = test::make_signed_bundle(60, 10);
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  const auto started = base::TimeTicks::Now();
  base::test::TestFuture<ResolveResult> future;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    future.GetCallback());
  const auto& result = future.Get();
  ASSERT_EQ(result.net_error, net::OK);
  ASSERT_TRUE(result.response);
  const auto& response = *result.response;
  ASSERT_EQ(response.status.code, pkresolve::StatusCode::Ok);
  const auto& resolution = response.resolution;
  EXPECT_EQ(resolution.service, fixture.service);
  EXPECT_EQ(resolution.url_port, 443);
  EXPECT_EQ(resolution.public_key, fixture.public_key);
  ASSERT_EQ(resolution.candidates.size(), 1u);
  const auto& endpoint = resolution.candidates[0];
  EXPECT_EQ(endpoint.port, 8443);
  EXPECT_EQ(endpoint.priority, 7);
  ASSERT_EQ(endpoint.addresses.size(), 1u);
  EXPECT_EQ(endpoint.addresses[0], "203.0.113.10");
  ASSERT_EQ(endpoint.protocols.size(), 1u);
  EXPECT_EQ(endpoint.protocols[0], pkresolve::HttpProtocol::Http2);
  // The packet was already observed ten seconds ago. Fetching it must not
  // restore the full sixty-second TTL. Allow one second for age rounding.
  EXPECT_GT(result.expires_at, started + base::Seconds(48));
  EXPECT_LE(result.expires_at, started + base::Seconds(50));
  EXPECT_EQ(factory_.total_requests(), 1u);
}

TEST_F(ResolverTest, AliasPreservesServiceAndReturnsDelegatedTlsKey) {
  const auto fixture = test::make_delegated_bundle();
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  base::test::TestFuture<ResolveResult> first;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    first.GetCallback());
  const auto& result = first.Get();
  ASSERT_EQ(result.net_error, net::OK);
  ASSERT_TRUE(result.response);
  ASSERT_EQ(result.response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_EQ(result.response->resolution.service, fixture.service);
  EXPECT_EQ(result.response->resolution.url_port, 443);
  EXPECT_EQ(result.response->resolution.public_key, fixture.public_key);
  ASSERT_EQ(result.response->resolution.candidates.size(), 1u);
  EXPECT_EQ(result.response->resolution.candidates[0].port, 8443);

  factory_.ClearResponses();
  base::test::TestFuture<ResolveResult> cached;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    cached.GetCallback());
  ASSERT_TRUE(cached.IsReady());
  ASSERT_TRUE(cached.Get().response);
  ASSERT_EQ(cached.Get().response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_EQ(cached.Get().response->resolution.service, fixture.service);
  EXPECT_EQ(cached.Get().response->resolution.public_key, fixture.public_key);
  EXPECT_LE(cached.Get().expires_at, result.expires_at);
  EXPECT_EQ(factory_.total_requests(), 1u);
}

TEST_F(ResolverTest, FreshCacheCompletesInlineWithoutAnotherRequest) {
  const auto fixture = test::make_signed_bundle(60, 10);
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  base::test::TestFuture<ResolveResult> first;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    first.GetCallback());
  ASSERT_TRUE(first.Get().response);
  ASSERT_EQ(first.Get().response->status.code, pkresolve::StatusCode::Ok);
  factory_.ClearResponses();

  base::test::TestFuture<ResolveResult> cached;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    cached.GetCallback());
  ASSERT_TRUE(cached.IsReady());
  ASSERT_TRUE(cached.Get().response);
  EXPECT_EQ(cached.Get().response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_EQ(cached.Get().response->resolution.public_key, fixture.public_key);
  EXPECT_LE(cached.Get().expires_at, first.Get().expires_at);
  EXPECT_EQ(factory_.total_requests(), 1u);
  EXPECT_EQ(factory_.NumPending(), 0);
}

TEST_F(ResolverTest, ExpiredCacheFetchesAndAcceptsFreshBundle) {
  const auto fixture = test::make_signed_bundle(2, 0);
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  base::test::TestFuture<ResolveResult> first;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    first.GetCallback());
  ASSERT_TRUE(first.Get().response);
  ASSERT_EQ(first.Get().response->status.code, pkresolve::StatusCode::Ok);
  factory_.ClearResponses();

  // Rust uses its own real clock. Advancing TaskEnvironment's mock time would
  // not expire the packet, so wait beyond its two-second TTL in real time.
  base::PlatformThread::Sleep(base::Seconds(3));
  base::test::TestFuture<ResolveResult> refreshed;
  resolver_.Resolve(std::string(fixture.service), 443, kProtocols,
                    refreshed.GetCallback());
  EXPECT_FALSE(refreshed.IsReady());
  EXPECT_EQ(factory_.total_requests(), 2u);
  ASSERT_EQ(factory_.NumPending(), 1);
  const auto fresh = test::make_signed_bundle(60, 0);
  ASSERT_EQ(fresh.service, fixture.service);
  ASSERT_TRUE(factory_.SimulateResponseForPendingRequest(
      kEndpoint, std::string(fresh.bundle)));
  ASSERT_TRUE(refreshed.Get().response);
  EXPECT_EQ(refreshed.Get().response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_GT(refreshed.Get().expires_at, first.Get().expires_at);
}

TEST_F(ResolverTest, NetworkCompletionCallbackCanDestroyResolver) {
  const auto fixture = test::make_signed_bundle(60, 0);
  auto resolver = std::make_unique<Resolver>(factory_.GetSafeWeakWrapper(),
                                             GURL(kEndpoint));
  base::test::TestFuture<ResolveResult> future;
  resolver->Resolve(
      std::string(fixture.service), 443, kProtocols,
      base::BindLambdaForTesting([&resolver, &future](ResolveResult result) {
        resolver.reset();
        future.SetValue(std::move(result));
      }));
  ASSERT_TRUE(factory_.SimulateResponseForPendingRequest(
      kEndpoint, std::string(fixture.bundle)));
  ASSERT_TRUE(future.Get().response);
  EXPECT_EQ(future.Get().response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_FALSE(resolver);
}

TEST_F(ResolverTest, CacheCompletionCallbackCanDestroyResolver) {
  const auto fixture = test::make_signed_bundle(60, 0);
  auto resolver = std::make_unique<Resolver>(factory_.GetSafeWeakWrapper(),
                                             GURL(kEndpoint));
  factory_.AddResponse(kEndpoint, std::string(fixture.bundle));
  base::test::TestFuture<ResolveResult> first;
  resolver->Resolve(std::string(fixture.service), 443, kProtocols,
                    first.GetCallback());
  ASSERT_TRUE(first.Get().response);
  ASSERT_EQ(first.Get().response->status.code, pkresolve::StatusCode::Ok);
  factory_.ClearResponses();

  base::test::TestFuture<ResolveResult> cached;
  resolver->Resolve(
      std::string(fixture.service), 443, kProtocols,
      base::BindLambdaForTesting([&resolver, &cached](ResolveResult result) {
        resolver.reset();
        cached.SetValue(std::move(result));
      }));
  EXPECT_FALSE(resolver);
  ASSERT_TRUE(cached.IsReady());
  ASSERT_TRUE(cached.Get().response);
  EXPECT_EQ(cached.Get().response->status.code, pkresolve::StatusCode::Ok);
  EXPECT_EQ(factory_.total_requests(), 1u);
}

}  // namespace
}  // namespace pubky::prototype

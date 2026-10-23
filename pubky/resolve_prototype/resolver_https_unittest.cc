// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <atomic>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/memory/ref_counted.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_status_code.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "pubky/resolve_prototype/resolver.h"
#include "pubky/resolve_prototype/signed_bundle_fixture.rs.h"
#include "services/network/network_context.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/originating_process_id.h"
#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"
#include "services/network/test/test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky::prototype {
namespace {

class ResolverHttpsTest : public testing::Test {
 protected:
  scoped_refptr<network::SharedURLLoaderFactory> CreateFactory() {
    // Use real certificate verification with the embedded server's scoped
    // test CA. No mock verifier or certificate-error bypass is installed.
    cert_verifier_ = net::CertVerifier::CreateDefault(nullptr);
    network::NetworkContext::SetCertVerifierForTesting(cert_verifier_.get());
    network_service_ = network::NetworkService::CreateForTesting();
    network_context_ = network::NetworkContext::CreateForTesting(
        network_service_.get(), context_remote_.BindNewPipeAndPassReceiver(),
        network::CreateNetworkContextParamsForTesting(), {});
    mojo::PendingRemote<network::mojom::URLLoaderFactory> factory;
    auto params = network::mojom::URLLoaderFactoryParams::New();
    params->process_id = network::OriginatingProcessId::browser();
    network_context_->CreateURLLoaderFactory(
        factory.InitWithNewPipeAndPassReceiver(), std::move(params));
    return base::MakeRefCounted<network::WrapperSharedURLLoaderFactory>(
        std::move(factory));
  }

  void TearDown() override {
    context_remote_.reset();
    network_context_.reset();
    network_service_.reset();
    network::NetworkContext::SetCertVerifierForTesting(nullptr);
    cert_verifier_.reset();
    task_environment_.RunUntilIdle();
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::MainThreadType::IO};
  const std::vector<pkresolve::HttpProtocol> protocols_ = {
      pkresolve::HttpProtocol::Http2, pkresolve::HttpProtocol::Http11};

 private:
  std::unique_ptr<net::CertVerifier> cert_verifier_;
  std::unique_ptr<network::NetworkService> network_service_;
  mojo::Remote<network::mojom::NetworkContext> context_remote_;
  std::unique_ptr<network::NetworkContext> network_context_;
};

// Explicit opt-in: this sends the supplied service name to the public relay.
TEST_F(ResolverHttpsTest, DISABLED_ResolvesDomainThroughPkarrDev) {
  const std::string service =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "pubky-service");
  ASSERT_FALSE(service.empty()) << "Pass --pubky-service=<canonical hostname>";
  // NetTestSuite maps hostnames to loopback. Only this explicit live test
  // permits a system DNS lookup for the public bundle service.
  auto host_resolver =
      base::MakeRefCounted<net::RuleBasedHostResolverProc>(nullptr);
  host_resolver->AllowDirectLookup("pkarr.dev");
  net::ScopedDefaultHostResolverProc scoped_host_resolver(host_resolver.get());
  Resolver resolver(CreateFactory());
  base::test::TestFuture<ResolveResult> future;
  resolver.Resolve(service, 443, protocols_, future.GetCallback());
  const auto& result = future.Get();
  ASSERT_EQ(result.net_error, net::OK);
  ASSERT_TRUE(result.response);
  ASSERT_EQ(result.response->status.code, pkresolve::StatusCode::Ok)
      << std::string(result.response->status.message);
  const auto& resolution = result.response->resolution;
  EXPECT_EQ(std::string(resolution.service), service);
  EXPECT_EQ(resolution.url_port, 443);
  EXPECT_GT(result.expires_at, base::TimeTicks::Now());
  ASSERT_FALSE(resolution.candidates.empty());
  std::cout << "Service: " << std::string(resolution.service) << '\n';
  for (const auto& candidate : resolution.candidates) {
    for (const auto& address : candidate.addresses) {
      std::cout << "Endpoint: " << std::string(address) << ':' << candidate.port
                << " priority=" << candidate.priority << '\n';
    }
  }
}

TEST_F(ResolverHttpsTest, ResolvesSignedBundleOverHttpsAndReusesCache) {
  const auto fixture = test::make_signed_bundle(60, 10);
  net::EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::atomic<int> request_count = 0;
  base::test::TestFuture<net::test_server::HttpRequest> received;
  server.RegisterRequestHandler(base::BindLambdaForTesting(
      [&request_count, bundle = std::string(fixture.bundle),
       callback = received.GetSequenceBoundRepeatingCallback()](
          const net::test_server::HttpRequest& request)
          -> std::unique_ptr<net::test_server::HttpResponse> {
        ++request_count;
        callback.Run(request);
        auto response = std::make_unique<net::test_server::BasicHttpResponse>();
        response->set_code(net::HTTP_OK);
        response->set_content_type("application/json");
        response->set_content(bundle);
        return response;
      }));
  // The handle stops the server before the request captures are destroyed.
  auto server_handle = server.StartAndReturnHandle();
  ASSERT_TRUE(server_handle);
  Resolver resolver(CreateFactory(), server.GetURL("/v1/resolve"));
  base::test::TestFuture<ResolveResult> first;
  resolver.Resolve(std::string(fixture.service), 443, protocols_,
                   first.GetCallback());
  const auto& result = first.Get();
  ASSERT_EQ(result.net_error, net::OK);
  ASSERT_TRUE(result.response);
  ASSERT_EQ(result.response->status.code, pkresolve::StatusCode::Ok);
  const auto& resolution = result.response->resolution;
  EXPECT_EQ(resolution.public_key, fixture.public_key);
  EXPECT_EQ(resolution.service, fixture.service);
  EXPECT_EQ(resolution.url_port, 443);
  ASSERT_EQ(resolution.candidates.size(), 1u);
  const auto& endpoint = resolution.candidates[0];
  ASSERT_EQ(endpoint.addresses.size(), 1u);
  EXPECT_EQ(endpoint.addresses[0], "203.0.113.10");
  EXPECT_EQ(endpoint.port, 8443);
  ASSERT_EQ(endpoint.protocols.size(), 1u);
  EXPECT_EQ(endpoint.protocols[0], pkresolve::HttpProtocol::Http2);
  EXPECT_GT(result.expires_at, base::TimeTicks::Now());
  EXPECT_LE(result.expires_at, base::TimeTicks::Now() + base::Seconds(50));

  const auto& request = received.Get();
  EXPECT_EQ(request.method, net::test_server::METHOD_POST);
  EXPECT_EQ(request.relative_url, "/v1/resolve");
  EXPECT_FALSE(request.headers.contains("Cookie"));
  EXPECT_FALSE(request.headers.contains("Authorization"));
  const auto body =
      base::JSONReader::ReadDict(request.content, base::JSON_PARSE_RFC);
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->FindString("service"));
  EXPECT_EQ(*body->FindString("service"), std::string(fixture.service));
  EXPECT_EQ(body->FindInt("url_port"), 443);
  const auto* alpn = body->FindList("supported_alpn");
  ASSERT_TRUE(alpn);
  ASSERT_EQ(alpn->size(), 2u);
  EXPECT_EQ((*alpn)[0].GetString(), "h2");
  EXPECT_EQ((*alpn)[1].GetString(), "http/1.1");

  base::test::TestFuture<ResolveResult> cached;
  resolver.Resolve(std::string(fixture.service), 443, protocols_,
                   cached.GetCallback());
  ASSERT_TRUE(cached.IsReady());
  ASSERT_TRUE(cached.Get().response);
  EXPECT_EQ(cached.Get().response->status.code, pkresolve::StatusCode::Ok);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(request_count.load(), 1);
}

TEST_F(ResolverHttpsTest, RejectsMismatchedServerCertificate) {
  net::EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTPS);
  server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  auto server_handle = server.StartAndReturnHandle();
  ASSERT_TRUE(server_handle);
  const auto fixture = test::make_signed_bundle(60, 0);
  Resolver resolver(CreateFactory(), server.GetURL("/v1/resolve"));
  base::test::TestFuture<ResolveResult> future;
  resolver.Resolve(std::string(fixture.service), 443, protocols_,
                   future.GetCallback());
  EXPECT_EQ(future.Get().net_error, net::ERR_CERT_COMMON_NAME_INVALID);
  EXPECT_FALSE(future.Get().response);
}

TEST_F(ResolverHttpsTest, RejectsRedirectWithoutFetchingDestination) {
  net::EmbeddedTestServer server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::atomic<int> request_count = 0;
  server.RegisterRequestHandler(base::BindLambdaForTesting(
      [&request_count](const net::test_server::HttpRequest& request)
          -> std::unique_ptr<net::test_server::HttpResponse> {
        ++request_count;
        auto response = std::make_unique<net::test_server::BasicHttpResponse>();
        response->set_code(net::HTTP_TEMPORARY_REDIRECT);
        response->AddCustomHeader("Location", "/unexpected");
        return response;
      }));
  auto server_handle = server.StartAndReturnHandle();
  ASSERT_TRUE(server_handle);
  const auto fixture = test::make_signed_bundle(60, 0);
  Resolver resolver(CreateFactory(), server.GetURL("/v1/resolve"));
  base::test::TestFuture<ResolveResult> future;
  resolver.Resolve(std::string(fixture.service), 443, protocols_,
                   future.GetCallback());
  EXPECT_EQ(future.Get().net_error, net::ERR_FAILED);
  EXPECT_FALSE(future.Get().response);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(request_count.load(), 1);
}

}  // namespace
}  // namespace pubky::prototype

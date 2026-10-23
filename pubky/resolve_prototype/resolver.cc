// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pubky/resolve_prototype/resolver.h"

#include <utility>

#include "base/functional/bind.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/mojom/fetch_api.mojom.h"

namespace pubky::prototype {
namespace {

// Experimental transport bounds, not a production protocol policy.
constexpr size_t kMaxBundleBytes = 1024 * 1024;
constexpr base::TimeDelta kFetchTimeout = base::Seconds(10);

constexpr auto kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_pkresolve_prototype", R"(
      semantics {
        sender: "Pubky resolution prototype"
        description:
          "Fetches signed endpoint records for an explicitly requested Pubky "
          "service. Rust derives connection candidates from the response."
        trigger: "Explicit invocation of the isolated resolution prototype."
        data: "Service hostname, original port, and supported HTTP protocols."
        destination: OTHER
        destination_other: "The explicitly configured HTTPS bundle service."
      }
      policy {
        cookies_allowed: NO
        setting: "Not connected to browser navigation or enabled by default."
        policy_exception_justification: "Development prototype only."
      })");

ResolveResult TransportFailure(int error) {
  ResolveResult result;
  result.net_error = error;
  return result;
}

}  // namespace

Resolver::Resolver(scoped_refptr<network::SharedURLLoaderFactory> factory,
                   GURL service_endpoint)
    : factory_(std::move(factory)),
      service_endpoint_(std::move(service_endpoint)),
      client_(pkresolve::new_client()) {}

Resolver::~Resolver() {
  Cancel();
}

void Resolver::Resolve(const std::string& service,
                       uint16_t url_port,
                       const std::vector<pkresolve::HttpProtocol>& protocols,
                       Callback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (loader_) {
    std::move(callback).Run(TransportFailure(net::ERR_UNEXPECTED));
    return;
  }
  // Never send credentials embedded in an endpoint, or accept cleartext HTTP.
  if (!factory_ || !service_endpoint_.is_valid() ||
      !service_endpoint_.SchemeIs("https") ||
      service_endpoint_.has_username() || service_endpoint_.has_password() ||
      service_endpoint_.has_ref()) {
    std::move(callback).Run(TransportFailure(net::ERR_INVALID_ARGUMENT));
    return;
  }

  const auto started = base::TimeTicks::Now();
  auto preparation =
      client_->prepare(service, url_port, {protocols.data(), protocols.size()});
  if (!preparation->needs_bundle()) {
    CompleteRust(pkresolve::prepared_result(std::move(preparation)), started,
                 std::move(callback));
    return;
  }

  auto request = std::make_unique<network::ResourceRequest>();
  request->url = service_endpoint_;
  request->method = "POST";
  request->credentials_mode = network::mojom::CredentialsMode::kOmit;
  request->redirect_mode = network::mojom::RedirectMode::kError;
  request->load_flags = net::LOAD_DISABLE_CACHE;
  loader_ =
      network::SimpleURLLoader::Create(std::move(request), kTrafficAnnotation);
  const auto body = preparation->request_body();
  loader_->AttachStringForUpload(std::string(body.data(), body.size()),
                                 "application/json");
  loader_->SetTimeoutDuration(kFetchTimeout);
  preparation_.emplace(std::move(preparation));
  callback_ = std::move(callback);
  loader_->DownloadToString(
      factory_.get(),
      base::BindOnce(&Resolver::OnDownloaded, weak_factory_.GetWeakPtr()),
      kMaxBundleBytes);
}

void Resolver::Cancel() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  weak_factory_.InvalidateWeakPtrs();
  loader_.reset();
  preparation_.reset();
  callback_.Reset();
}

void Resolver::OnDownloaded(std::optional<std::string> body) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  const int error = loader_->NetError();
  loader_.reset();
  auto callback = std::move(callback_);
  auto preparation = std::move(*preparation_);
  preparation_.reset();

  // SimpleURLLoader rejects non-2xx statuses and oversized bodies by default.
  if (error != net::OK || !body) {
    std::move(callback).Run(
        TransportFailure(error == net::OK ? net::ERR_INVALID_RESPONSE : error));
    return;
  }
  const auto started = base::TimeTicks::Now();
  auto response = client_->accept_bundle(
      std::move(preparation),
      {reinterpret_cast<const uint8_t*>(body->data()), body->size()});
  CompleteRust(std::move(response), started, std::move(callback));
}

void Resolver::CompleteRust(pkresolve::ResolveResponse response,
                            base::TimeTicks started,
                            Callback callback) {
  ResolveResult result;
  if (response.status.code == pkresolve::StatusCode::Ok) {
    result.expires_at =
        started + base::Milliseconds(response.resolution.valid_for_ms);
    if (result.expires_at <= base::TimeTicks::Now()) {
      std::move(callback).Run(TransportFailure(net::ERR_DNS_TIMED_OUT));
      return;
    }
  }
  result.response.emplace(std::move(response));
  // Nothing accesses this after delivery: the callback may destroy the resolver
  // or start another lookup.
  std::move(callback).Run(std::move(result));
}

}  // namespace pubky::prototype

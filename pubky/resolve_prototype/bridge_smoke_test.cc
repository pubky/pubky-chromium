// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Standalone test of the actual CXX boundary, using a freshly signed fixture.
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "pkresolve.h"

namespace {
bool Check(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
  }
  return condition;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: bridge_smoke_test <service> <bundle-file>\n";
    return 1;
  }
  const std::vector protocols = {pkresolve::HttpProtocol::Http2,
                                 pkresolve::HttpProtocol::Http11};
  const rust::Slice<const pkresolve::HttpProtocol> supported(protocols.data(),
                                                             protocols.size());
  auto client = pkresolve::new_client();
  auto invalid = client->prepare("example.com", 443, supported);
  if (!Check(!invalid->needs_bundle(), "invalid input requested HTTP") ||
      !Check(pkresolve::prepared_result(std::move(invalid)).status.code ==
                 pkresolve::StatusCode::InvalidInput,
             "invalid input was accepted")) {
    return 1;
  }
  auto preparation = client->prepare(argv[1], 443, supported);
  auto delayed = client->prepare(argv[1], 443, supported);
  if (!Check(preparation->needs_bundle(), "empty cache did not request HTTP") ||
      !Check(!preparation->request_body().empty(), "empty HTTP body")) {
    return 1;
  }
  std::ifstream input(argv[2], std::ios::binary);
  if (!input) {
    std::cerr << "could not open bundle\n";
    return 1;
  }
  const std::vector<std::uint8_t> body((std::istreambuf_iterator<char>(input)),
                                       std::istreambuf_iterator<char>());
  const auto started = std::chrono::steady_clock::now();
  auto response =
      client->accept_bundle(std::move(preparation), {body.data(), body.size()});
  if (!Check(response.status.code == pkresolve::StatusCode::Ok,
             "fixture failed to resolve")) {
    return 1;
  }
  const auto deadline =
      started + std::chrono::milliseconds(response.resolution.valid_for_ms);
  if (!Check(response.resolution.candidates.size() == 1,
             "unexpected candidate count") ||
      !Check(deadline > std::chrono::steady_clock::now(), "expired result")) {
    return 1;
  }
  const auto& candidate = response.resolution.candidates[0];
  if (!Check(candidate.port == 443 && candidate.addresses.size() == 1,
             "unexpected endpoint")) {
    return 1;
  }
  const auto& address = candidate.addresses[0];
  if (!Check(std::string(address.data(), address.size()) == "203.0.113.10",
             "unexpected address")) {
    return 1;
  }
  auto cached = client->prepare(argv[1], 443, supported);
  if (!Check(!cached->needs_bundle(), "warm cache requested HTTP")) {
    return 1;
  }
  auto cached_response = pkresolve::prepared_result(std::move(cached));
  if (!Check(cached_response.status.code == pkresolve::StatusCode::Ok,
             "cached resolution failed") ||
      !Check(cached_response.resolution.valid_for_ms <=
                 response.resolution.valid_for_ms,
             "cache extended freshness")) {
    return 1;
  }
  // A delayed invalid response must leave the accepted cache intact.
  const std::string malformed = "invalid JSON";
  auto failed = client->accept_bundle(
      std::move(delayed),
      {reinterpret_cast<const std::uint8_t*>(malformed.data()),
       malformed.size()});
  if (!Check(failed.status.code == pkresolve::StatusCode::InvalidBundle,
             "malformed bundle accepted")) {
    return 1;
  }
  auto retained = client->prepare(argv[1], 443, supported);
  if (!Check(!retained->needs_bundle(), "failed response damaged cache") ||
      !Check(pkresolve::prepared_result(std::move(retained)).status.code ==
                 pkresolve::StatusCode::Ok,
             "retained cache failed")) {
    return 1;
  }
  std::cout << "PASS: CXX resolution, endpoint, cache reuse, freshness, input "
               "and bundle errors\n";
}

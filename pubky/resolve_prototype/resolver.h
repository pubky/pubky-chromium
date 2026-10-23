// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PUBKY_RESOLVE_PROTOTYPE_RESOLVER_H_
#define PUBKY_RESOLVE_PROTOTYPE_RESOLVER_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "base/time/time.h"
#include "third_party/pkarr/bindings/chromium/src/lib.rs.h"
#include "url/gurl.h"

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

namespace pubky::prototype {

// A successful transport can still produce a Rust protocol error. Inspect
// response->status before using endpoints. Preserve expires_at across copies.
struct ResolveResult {
  int net_error = 0;
  std::optional<pkresolve::ResolveResponse> response;
  base::TimeTicks expires_at;
};

// Experimental Pubky service resolver. Own one per isolated network context and
// use it on one sequence. It permits one active lookup; use separate instances
// for parallel experiments. No browser navigation code instantiates this class.
class Resolver {
 public:
  using Callback = base::OnceCallback<void(ResolveResult)>;

  Resolver(scoped_refptr<network::SharedURLLoaderFactory> factory,
           GURL service_endpoint = GURL("https://pkarr.dev/v1/resolve"));
  ~Resolver();
  Resolver(const Resolver&) = delete;
  Resolver& operator=(const Resolver&) = delete;

  // Input is a canonical key hostname, optionally scoped, not a URL. The port
  // is the original URL port. Cache hits and input errors can complete inline.
  // A lookup while HTTP is active fails with ERR_UNEXPECTED without disturbing
  // the active lookup. The caller supplies the profile-isolated factory.
  void Resolve(const std::string& service,
               uint16_t url_port,
               const std::vector<pkresolve::HttpProtocol>& protocols,
               Callback callback);

  // Cancel HTTP and suppress delivery. Retains the Rust cache. Destruction also
  // cancels; callers must cancel when their own lifetime ends.
  void Cancel();

 private:
  void OnDownloaded(std::optional<std::string> body);
  void CompleteRust(pkresolve::ResolveResponse response,
                    base::TimeTicks started,
                    Callback callback);

  scoped_refptr<network::SharedURLLoaderFactory> factory_;
  const GURL service_endpoint_;
  rust::Box<pkresolve::Client> client_;
  std::optional<rust::Box<pkresolve::Preparation>> preparation_;
  std::unique_ptr<network::SimpleURLLoader> loader_;
  Callback callback_;
  SEQUENCE_CHECKER(sequence_checker_);
  base::WeakPtrFactory<Resolver> weak_factory_{this};
};

}  // namespace pubky::prototype

#endif  // PUBKY_RESOLVE_PROTOTYPE_RESOLVER_H_

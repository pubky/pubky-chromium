// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_PUBKY_SESSION_SERVICE_H_
#define COMPONENTS_PUBKY_SESSION_PUBKY_SESSION_SERVICE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/observer_list_types.h"
#include "base/sequence_checker.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "components/keyed_service/core/keyed_service.h"
#include "components/pubky_session/core/approval.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "components/pubky_session/core/signin_link.h"
#include "components/pubky_session/session_store.h"

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

namespace os_crypt_async {
class Encryptor;
class OSCryptAsync;
}  // namespace os_crypt_async

namespace pubky_session {

// Holds one profile's Pubky grant: signs in through Pubky Ring or Passport,
// keeps a valid bearer, persists everything encrypted, and signs out. See
// pubky/SESSIONS.md. Credentials never leave this object except as a bearer
// handed to browser-side callers.
class PubkySessionService : public KeyedService {
 public:
  enum class State {
    // Reading the stored session.
    kLoading,
    kSignedOut,
    // A sign-in link is shown and the browser waits for the signer.
    kWaitingForApproval,
    kSignedIn,
    // The grant expired or the homeserver rejected it. The identity is still
    // known; the user approves again to continue.
    kApprovalExpired,
  };

  enum class SignInResult {
    kSignedIn,
    kCancelled,
    kTimedOut,
    // The approval was invalid or not for this request.
    kRejected,
    kHomeserverNotFound,
    kExchangeFailed,
    kNetworkError,
  };

  enum class StorageMethod { kGet, kPut, kDelete, kList };

  // One call to the user's homeserver storage on behalf of a site. The caller
  // has already checked the site's scope; the service picks the grant.
  struct StorageRequest {
    StorageRequest();
    StorageRequest(StorageRequest&&);
    StorageRequest& operator=(StorageRequest&&);
    ~StorageRequest();

    StorageMethod method = StorageMethod::kGet;
    // A canonical storage path. kList takes a directory, ending in '/'.
    std::string path;
    // kPut only.
    std::string body;
    std::string content_type;
    // kList only.
    std::optional<uint16_t> limit;
    std::string cursor;
    bool shallow = false;
    bool reverse = false;
  };

  enum class StorageStatus {
    kOk,
    kNotFound,
    // No grant covers the request: signed out, approval expired, or a write
    // or private read without an approved scope.
    kNotSignedIn,
    // The homeserver refused the bearer.
    kForbidden,
    kTooLarge,
    kNetworkError,
  };

  struct StorageResponse {
    StorageResponse();
    StorageResponse(StorageResponse&&);
    StorageResponse& operator=(StorageResponse&&);
    ~StorageResponse();

    StorageStatus status = StorageStatus::kNetworkError;
    std::string content_type;
    std::string body;
  };

  class Observer : public base::CheckedObserver {
   public:
    virtual void OnPubkySessionChanged() = 0;
  };

  // Endpoints and limits, replaceable in tests.
  struct Config {
    Config();
    Config(const Config&);
    Config& operator=(const Config&);
    ~Config();

    std::string relay_inbox = kDefaultRelayInbox;
    std::vector<std::string> pkarr_relays = {"https://pkarr.pubky.app",
                                             "https://pkarr.pubky.org"};
    // How long a sign-in link stays valid. Relays keep a message for about
    // five minutes.
    base::TimeDelta sign_in_timeout = base::Minutes(5);
    // One relay long-poll. The relay itself answers 408 after about 25 s.
    base::TimeDelta relay_poll_timeout = base::Seconds(30);
    // Refresh this long before the bearer expires.
    base::TimeDelta refresh_margin = base::Minutes(1);
  };

  // `url_loader_factory` is the profile's browser-process factory. An empty
  // `storage_path` keeps the session in memory only, for Incognito; it is then
  // revoked on Shutdown() through `shutdown_url_loader_factory`, which must
  // outlive the profile.
  PubkySessionService(
      scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
      scoped_refptr<network::SharedURLLoaderFactory>
          shutdown_url_loader_factory,
      os_crypt_async::OSCryptAsync* os_crypt_async,
      base::FilePath storage_path,
      Config config = Config());
  PubkySessionService(const PubkySessionService&) = delete;
  PubkySessionService& operator=(const PubkySessionService&) = delete;
  ~PubkySessionService() override;

  // KeyedService:
  void Shutdown() override;

  State state() const;

  // The `pubkyauth://signin_grant` link to show as a QR code or open in a
  // signer, while waiting for approval. Empty otherwise.
  std::string signin_link() const;

  // The signed-in identity, also known while the approval is expired.
  std::optional<Key> user() const;
  std::optional<Key> homeserver() const;
  // Everything the browser's approval covers: the sign-in grant's
  // capabilities and those of scope grants added later.
  std::vector<Capability> capabilities() const;

  // The `name` from the user's own /pub/pubky.app/profile.json, read from
  // their homeserver once signed in. Empty until it arrives or if unset.
  std::optional<std::string> display_name() const;

  // The outcome of the last sign-in attempt, cleared when a new one starts.
  std::optional<SignInResult> last_sign_in_result() const;

  // Starts a sign-in for /pub/:rw. Allowed when signed out or when the
  // approval expired; `callback` runs once with the outcome.
  using SignInCallback = base::OnceCallback<void(SignInResult)>;
  void StartSignIn(SignInCallback callback);
  void CancelSignIn();

  // Starts a Pubky Ring approval for `capabilities`, which the browser's
  // approval does not cover yet, such as a site's /priv/ path. The approved
  // grant is added to the session next to the sign-in grant. Only while signed
  // in and no other approval is pending; `callback` runs once with the
  // outcome, kSignedIn when the grant was added. Capabilities with the `e`
  // action are refused.
  void RequestScopes(std::vector<Capability> capabilities,
                     SignInCallback callback);

  // The link and capabilities of the pending scope approval, for the Ring
  // prompt. Empty otherwise.
  std::string scope_approval_link() const;
  std::vector<Capability> pending_scope_capabilities() const;

  // Revokes every grant on the homeserver (best effort) and deletes the
  // stored session at once.
  void SignOut();

  // A bearer valid for at least `refresh_margin`, refreshing it first when
  // needed. Runs with nullopt when not signed in.
  using BearerCallback =
      base::OnceCallback<void(std::optional<std::string> bearer)>;
  void GetBearer(BearerCallback callback);

  // Sends `request` to the user's homeserver with the bearer of the grant that
  // covers its path. Public reads go out without a bearer when no grant is
  // valid. `callback` always runs.
  using StorageCallback = base::OnceCallback<void(StorageResponse)>;
  void SendStorageRequest(StorageRequest request, StorageCallback callback);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  const SigninGrantRequest* pending_request_for_testing() const;
  // Puts the service in the signed-in state without the network.
  void SignInForTesting(StoredSession session,
                        std::optional<std::string> display_name);

 private:
  struct PendingSignIn;

  struct ScopeRefresh {
    ScopeRefresh();
    ScopeRefresh(ScopeRefresh&&);
    ScopeRefresh& operator=(ScopeRefresh&&);
    ~ScopeRefresh();

    std::unique_ptr<network::SimpleURLLoader> loader;
    std::vector<BearerCallback> callbacks;
  };

  void OnEncryptorReady(scoped_refptr<os_crypt_async::Encryptor> encryptor);
  void OnStoredDataRead(std::optional<std::string> data);
  void SetState(State state);

  // Sign-in steps.
  void PollRelay();
  void OnRelayResponse(std::optional<std::string> body);
  void RetryRelayAfterError();
  void AcknowledgeRelay(const std::string& channel_url);
  void FetchHomeserverRecord();
  void OnHomeserverRecord(std::optional<std::string> body);
  void ExchangeGrant();
  void OnExchangeResponse(std::optional<std::string> body);
  void FinishSignIn(SignInResult result);
  void StartApproval(std::vector<Capability> capabilities,
                     bool adds_scopes,
                     SignInCallback callback);

  // Bearer upkeep.
  void ScheduleRefresh();
  void Refresh();
  void OnRefreshResponse(std::optional<std::string> body);
  void RunBearerCallbacks();

  // Scope grants.
  void GetBearerFor(const Capability& needed, BearerCallback callback);
  ScopeGrant* FindScopeGrant(const std::string& grant_id);
  void RemoveExpiredScopeGrants();
  void RefreshScopeGrant(const std::string& grant_id, BearerCallback callback);
  void OnScopeRefreshResponse(const std::string& grant_id,
                              std::optional<std::string> body);
  void CancelScopeRefreshes();

  // Storage.
  void StartStorageRequest(StorageRequest request,
                           StorageCallback callback,
                           std::optional<std::string> bearer);
  void OnStorageResponse(int loader_id,
                         StorageCallback callback,
                         std::optional<std::string> body);

  // The user's own public profile, for the display name.
  void FetchProfile();
  void OnProfileResponse(std::optional<std::string> body);

  void Persist();
  void DeleteStoredSession();
  // Revokes the sign-in grant and every scope grant.
  void SendLogout(scoped_refptr<network::SharedURLLoaderFactory> factory);

  SEQUENCE_CHECKER(sequence_checker_);

  const scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
  const scoped_refptr<network::SharedURLLoaderFactory>
      shutdown_url_loader_factory_;
  const base::FilePath storage_path_;
  const Config config_;
  const scoped_refptr<base::SequencedTaskRunner> file_task_runner_;

  scoped_refptr<os_crypt_async::Encryptor> encryptor_;
  State state_ = State::kLoading;
  // Present when signed in or expired.
  std::optional<StoredSession> session_;
  // A sign-in, or a scope approval while signed in. One at a time.
  std::unique_ptr<PendingSignIn> pending_;
  // The sign-in grant's refresh.
  std::unique_ptr<network::SimpleURLLoader> loader_;
  std::unique_ptr<network::SimpleURLLoader> profile_loader_;
  // Scope grant refreshes, by grant ID.
  std::map<std::string, ScopeRefresh> scope_refreshes_;
  std::map<int, std::unique_ptr<network::SimpleURLLoader>> storage_loaders_;
  int next_storage_loader_id_ = 0;
  std::optional<std::string> display_name_;
  std::optional<SignInResult> last_sign_in_result_;
  bool refreshing_ = false;
  std::vector<BearerCallback> bearer_callbacks_;
  base::OneShotTimer refresh_timer_;
  base::ObserverList<Observer> observers_;

  base::WeakPtrFactory<PubkySessionService> weak_factory_{this};
};

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_PUBKY_SESSION_SERVICE_H_

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/pubky_session_service.h"

#include <algorithm>
#include <tuple>
#include <utility>

#include "base/files/file_util.h"
#include "base/files/important_file_writer.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/notreached.h"
#include "base/strings/escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/thread_pool.h"
#include "base/values.h"
#include "components/os_crypt/async/browser/os_crypt_async.h"
#include "components/os_crypt/async/common/encryptor.h"
#include "components/pubky_session/core/grant_session.h"
#include "components/pubky_session/core/pkarr_packet.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_status_code.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "url/gurl.h"

namespace pubky_session {

namespace {

constexpr char kSignInCapabilities[] = "/pub/:rw";
constexpr size_t kMaxRelayMessageSize = 64 * 1024;
constexpr size_t kMaxSessionResponseSize = 64 * 1024;
constexpr int kMaxRelayFailures = 3;
constexpr base::TimeDelta kRelayRetryDelay = base::Seconds(2);
constexpr base::TimeDelta kRequestTimeout = base::Seconds(30);
constexpr base::TimeDelta kRefreshRetryDelay = base::Seconds(30);
// The most SimpleURLLoader returns as a string; uploads use the same limit.
constexpr size_t kMaxStorageBodySize =
    network::SimpleURLLoader::kMaxBoundedStringDownloadSize;

constexpr net::NetworkTrafficAnnotationTag kRelayTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_session_relay", R"(
      semantics {
        sender: "Pubky session"
        description:
          "While the Pubky sign-in panel shows a sign-in link, the browser "
          "long-polls the HTTP relay named in that link for the signer's "
          "encrypted approval, then deletes the relay message."
        trigger: "The user starts signing in to the browser with Pubky."
        data:
          "A random channel ID derived from a per-sign-in secret. The "
          "approval is end-to-end encrypted; the relay cannot read it."
        user_data {
          type: NONE
        }
        destination: OTHER
        destination_other: "The Pubky HTTP relay, httprelay.pubky.app."
        internal {
          contacts {
            owners: "chrome/browser/OWNERS"
          }
        }
        last_reviewed: "2026-10-20"
      }
      policy {
        cookies_allowed: NO
        setting: "Only runs while the user signs in from the identity button."
        policy_exception_justification: "Explicit user action."
      })");

constexpr net::NetworkTrafficAnnotationTag kPkarrTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_session_pkarr", R"(
      semantics {
        sender: "Pubky session"
        description:
          "After the user approves the browser, it fetches the user's signed "
          "PKARR record from a pkarr relay to find their homeserver. The "
          "browser verifies the record's signature itself."
        trigger: "Completing a Pubky sign-in."
        data: "The user's public key."
        user_data {
          type: OTHER
        }
        destination: OTHER
        destination_other: "Pkarr relays, pkarr.pubky.app and pkarr.pubky.org."
        internal {
          contacts {
            owners: "chrome/browser/OWNERS"
          }
        }
        last_reviewed: "2026-10-20"
      }
      policy {
        cookies_allowed: NO
        setting: "Only runs when the user signs in from the identity button."
        policy_exception_justification: "Explicit user action."
      })");

constexpr net::NetworkTrafficAnnotationTag kHomeserverTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_session_homeserver", R"(
      semantics {
        sender: "Pubky session"
        description:
          "Exchanges the user's Pubky grant for a short-lived bearer at their "
          "homeserver, refreshes it before it expires, and revokes the grant "
          "on sign-out."
        trigger:
          "Signing in, keeping a signed-in session valid, or signing out."
        data:
          "The grant the user approved and a proof that the browser holds "
          "its key."
        user_data {
          type: ACCESS_TOKEN
        }
        destination: OTHER
        destination_other: "The user's own Pubky homeserver."
        internal {
          contacts {
            owners: "chrome/browser/OWNERS"
          }
        }
        last_reviewed: "2026-10-20"
      }
      policy {
        cookies_allowed: NO
        setting: "Stops when the user signs out from the identity button."
        policy_exception_justification:
          "The user signed in explicitly; nothing is sent while signed out."
      })");

constexpr net::NetworkTrafficAnnotationTag kProfileTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_session_profile", R"(
      semantics {
        sender: "Pubky session"
        description:
          "Reads the signed-in user's own public profile, "
          "/pub/pubky.app/profile.json, from their homeserver to show their "
          "name on the identity button."
        trigger: "Signing in, or starting the browser while signed in."
        data: "The user's public key, as part of the request path."
        user_data {
          type: OTHER
        }
        destination: OTHER
        destination_other: "The user's own Pubky homeserver."
        internal {
          contacts {
            owners: "chrome/browser/OWNERS"
          }
        }
        last_reviewed: "2026-10-20"
      }
      policy {
        cookies_allowed: NO
        setting: "Stops when the user signs out from the identity button."
        policy_exception_justification:
          "Reads only the signed-in user's own public data."
      })");

constexpr net::NetworkTrafficAnnotationTag kStorageTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pubky_session_storage", R"(
      semantics {
        sender: "Pubky session"
        description:
          "Reads, writes, deletes and lists files in the signed-in user's "
          "Pubky storage for a site the user allowed, within the paths the "
          "user allowed for that site."
        trigger:
          "A site the user connected to their Pubky identity calls the "
          "navigator.pubky session API."
        data:
          "The storage path, the file the site writes, and the browser's "
          "bearer for the user's homeserver."
        user_data {
          type: ACCESS_TOKEN
          type: USER_CONTENT
        }
        destination: OTHER
        destination_other: "The user's own Pubky homeserver."
        internal {
          contacts {
            owners: "chrome/browser/OWNERS"
          }
        }
        last_reviewed: "2026-10-20"
      }
      policy {
        cookies_allowed: NO
        setting:
          "Only for sites the user allowed. Removing a site's access or "
          "signing out from the identity button stops it."
        policy_exception_justification:
          "Each site needs the user's permission first."
      })");

constexpr size_t kMaxProfileSize = 16 * 1024;
constexpr size_t kMaxDisplayNameBytes = 64;

// The `name` of a pubky.app profile, without control characters and cut to
// a size the toolbar can show.
std::optional<std::string> ParseProfileName(std::string_view json) {
  std::optional<base::DictValue> profile =
      base::JSONReader::ReadDict(json, base::JSON_PARSE_RFC);
  const std::string* name = profile ? profile->FindString("name") : nullptr;
  if (!name) {
    return std::nullopt;
  }
  std::string clean;
  for (char c : *name) {
    const unsigned char byte = static_cast<unsigned char>(c);
    if (byte >= 0x20 && byte != 0x7F) {
      clean.push_back(c);
    }
  }
  std::string truncated;
  base::TruncateUTF8ToByteSize(
      std::string(base::TrimWhitespaceASCII(clean, base::TRIM_ALL)),
      kMaxDisplayNameBytes, &truncated);
  if (truncated.empty()) {
    return std::nullopt;
  }
  return truncated;
}

std::unique_ptr<network::SimpleURLLoader> CreateLoader(
    const GURL& url,
    const std::string& method,
    const net::NetworkTrafficAnnotationTag& annotation,
    const std::string* bearer = nullptr) {
  auto request = std::make_unique<network::ResourceRequest>();
  request->url = url;
  request->method = method;
  if (bearer) {
    request->headers.SetHeader(net::HttpRequestHeaders::kAuthorization,
                               "Bearer " + *bearer);
  }
  request->credentials_mode = network::mojom::CredentialsMode::kOmit;
  request->referrer_policy = net::ReferrerPolicy::NO_REFERRER;
  request->load_flags = net::LOAD_DISABLE_CACHE;
  return network::SimpleURLLoader::Create(std::move(request), annotation);
}

int ResponseCode(const network::SimpleURLLoader& loader) {
  const network::mojom::URLResponseHead* head = loader.ResponseInfo();
  return head && head->headers ? head->headers->response_code() : 0;
}

GURL GrantSessionUrl(const Key& homeserver) {
  return GURL("https://" + EncodeZ32(homeserver) + kGrantSessionPath);
}

bool IsExpired(uint64_t unix_seconds) {
  return base::Time::Now() >=
         base::Time::FromTimeT(static_cast<time_t>(unix_seconds));
}

const char* HttpMethod(PubkySessionService::StorageMethod method) {
  switch (method) {
    case PubkySessionService::StorageMethod::kGet:
    case PubkySessionService::StorageMethod::kList:
      return "GET";
    case PubkySessionService::StorageMethod::kPut:
      return "PUT";
    case PubkySessionService::StorageMethod::kDelete:
      return "DELETE";
  }
  NOTREACHED();
}

bool IsWrite(PubkySessionService::StorageMethod method) {
  return method == PubkySessionService::StorageMethod::kPut ||
         method == PubkySessionService::StorageMethod::kDelete;
}

// Path-addressed storage: /storage/<user>/<path>, with each path segment
// escaped so that '?', '#' and '%' stay part of the path.
GURL StorageUrl(const Key& homeserver,
                const Key& user,
                const PubkySessionService::StorageRequest& request) {
  std::string url = "https://" + EncodeZ32(homeserver) + "/storage/" +
                    EncodeZ32(user) + base::EscapePath(request.path);
  if (request.method == PubkySessionService::StorageMethod::kList) {
    std::vector<std::string> query;
    if (request.limit) {
      query.push_back("limit=" + base::NumberToString(*request.limit));
    }
    if (!request.cursor.empty()) {
      query.push_back("cursor=" +
                      base::EscapeQueryParamValue(request.cursor,
                                                  /*use_plus=*/false));
    }
    if (request.shallow) {
      query.push_back("shallow=true");
    }
    if (request.reverse) {
      query.push_back("reverse=true");
    }
    if (!query.empty()) {
      url += "?" + base::JoinString(query, "&");
    }
  }
  return GURL(url);
}

// Sends a request whose answer does not matter. The loader deletes itself
// when the request completes.
void SendDetached(network::SharedURLLoaderFactory* factory,
                  std::unique_ptr<network::SimpleURLLoader> loader) {
  network::SimpleURLLoader* raw = loader.get();
  raw->DownloadHeadersOnly(
      factory, base::BindOnce(
                   [](std::unique_ptr<network::SimpleURLLoader>,
                      scoped_refptr<net::HttpResponseHeaders>) {},
                   std::move(loader)));
}

std::optional<std::string> ReadStoredFile(const base::FilePath& path) {
  std::string data;
  if (!base::ReadFileToString(path, &data)) {
    return std::nullopt;
  }
  return data;
}

void WriteStoredFile(const base::FilePath& path, const std::string& data) {
  std::ignore = base::ImportantFileWriter::WriteFileAtomically(path, data);
}

}  // namespace

struct PubkySessionService::PendingSignIn {
  // A scope approval for a signed-in session, rather than a sign-in.
  bool adds_scopes = false;
  SigninGrantRequest request;
  Key client_seed{};
  std::string link;
  base::TimeTicks deadline;
  SignInCallback callback;
  // Restored when the sign-in does not complete.
  State previous_state = State::kSignedOut;
  int consecutive_failures = 0;
  std::optional<GrantApproval> approval;
  size_t relay_index = 0;
  Key homeserver{};
  std::unique_ptr<network::SimpleURLLoader> loader;
  base::OneShotTimer retry_timer;
};

PubkySessionService::StorageRequest::StorageRequest() = default;
PubkySessionService::StorageRequest::StorageRequest(StorageRequest&&) = default;
PubkySessionService::StorageRequest&
PubkySessionService::StorageRequest::operator=(StorageRequest&&) = default;
PubkySessionService::StorageRequest::~StorageRequest() = default;

PubkySessionService::StorageResponse::StorageResponse() = default;
PubkySessionService::StorageResponse::StorageResponse(StorageResponse&&) =
    default;
PubkySessionService::StorageResponse&
PubkySessionService::StorageResponse::operator=(StorageResponse&&) = default;
PubkySessionService::StorageResponse::~StorageResponse() = default;

PubkySessionService::ScopeRefresh::ScopeRefresh() = default;
PubkySessionService::ScopeRefresh::ScopeRefresh(ScopeRefresh&&) = default;
PubkySessionService::ScopeRefresh&
PubkySessionService::ScopeRefresh::operator=(ScopeRefresh&&) = default;
PubkySessionService::ScopeRefresh::~ScopeRefresh() = default;

PubkySessionService::Config::Config() = default;
PubkySessionService::Config::Config(const Config&) = default;
PubkySessionService::Config& PubkySessionService::Config::operator=(
    const Config&) = default;
PubkySessionService::Config::~Config() = default;

PubkySessionService::PubkySessionService(
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory,
    scoped_refptr<network::SharedURLLoaderFactory> shutdown_url_loader_factory,
    os_crypt_async::OSCryptAsync* os_crypt_async,
    base::FilePath storage_path,
    Config config)
    : url_loader_factory_(std::move(url_loader_factory)),
      shutdown_url_loader_factory_(std::move(shutdown_url_loader_factory)),
      storage_path_(std::move(storage_path)),
      config_(std::move(config)),
      file_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::BLOCK_SHUTDOWN})) {
  if (storage_path_.empty() || !os_crypt_async) {
    state_ = State::kSignedOut;
    return;
  }
  os_crypt_async->GetInstance(
      base::BindOnce(&PubkySessionService::OnEncryptorReady,
                     weak_factory_.GetWeakPtr()));
}

PubkySessionService::~PubkySessionService() = default;

void PubkySessionService::Shutdown() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  refresh_timer_.Stop();
  loader_.reset();
  profile_loader_.reset();
  pending_.reset();
  scope_refreshes_.clear();
  storage_loaders_.clear();
  // An Incognito sign-in ends with its windows.
  if (storage_path_.empty() && session_ && shutdown_url_loader_factory_) {
    SendLogout(shutdown_url_loader_factory_);
  }
  session_.reset();
}

PubkySessionService::State PubkySessionService::state() const {
  return state_;
}

std::string PubkySessionService::signin_link() const {
  return pending_ && !pending_->adds_scopes ? pending_->link : std::string();
}

std::string PubkySessionService::scope_approval_link() const {
  return pending_ && pending_->adds_scopes ? pending_->link : std::string();
}

std::vector<Capability> PubkySessionService::pending_scope_capabilities()
    const {
  return pending_ && pending_->adds_scopes ? pending_->request.capabilities
                                           : std::vector<Capability>();
}

std::optional<Key> PubkySessionService::user() const {
  return session_ ? std::optional<Key>(session_->user) : std::nullopt;
}

std::optional<Key> PubkySessionService::homeserver() const {
  return session_ ? std::optional<Key>(session_->homeserver) : std::nullopt;
}

std::vector<Capability> PubkySessionService::capabilities() const {
  if (!session_) {
    return {};
  }
  std::vector<Capability> all = session_->capabilities;
  for (const ScopeGrant& grant : session_->scope_grants) {
    all.insert(all.end(), grant.capabilities.begin(), grant.capabilities.end());
  }
  return all;
}

std::optional<std::string> PubkySessionService::display_name() const {
  return display_name_;
}

std::optional<PubkySessionService::SignInResult>
PubkySessionService::last_sign_in_result() const {
  return last_sign_in_result_;
}

void PubkySessionService::StartSignIn(SignInCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ != State::kSignedOut && state_ != State::kApprovalExpired) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback), SignInResult::kCancelled));
    return;
  }
  // A scope approval left over from the expired session gives way.
  if (pending_) {
    FinishSignIn(SignInResult::kCancelled);
  }
  last_sign_in_result_.reset();
  StartApproval(*ParseCapabilities(kSignInCapabilities), /*adds_scopes=*/false,
                std::move(callback));
}

void PubkySessionService::RequestScopes(std::vector<Capability> capabilities,
                                        SignInCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  const bool asks_for_keys =
      std::ranges::any_of(capabilities, &Capability::encryption_keys);
  if (state_ != State::kSignedIn || pending_ || capabilities.empty() ||
      asks_for_keys) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback), SignInResult::kCancelled));
    return;
  }
  StartApproval(std::move(capabilities), /*adds_scopes=*/true,
                std::move(callback));
}

void PubkySessionService::StartApproval(std::vector<Capability> capabilities,
                                        bool adds_scopes,
                                        SignInCallback callback) {
  pending_ = std::make_unique<PendingSignIn>();
  pending_->adds_scopes = adds_scopes;
  pending_->previous_state = state_;
  // Scope grants are bound to the session's existing proof-of-possession key.
  pending_->client_seed = adds_scopes ? session_->client_seed : RandomKey();
  pending_->request.capabilities = std::move(capabilities);
  pending_->request.relay = config_.relay_inbox;
  pending_->request.client_public_key = Ed25519PublicKey(pending_->client_seed);
  pending_->request.format = ApprovalFormat::kBareGrant;
  pending_->request.channel_key = RandomKey();
  pending_->link = BuildSigninGrantLink(pending_->request);
  pending_->deadline = base::TimeTicks::Now() + config_.sign_in_timeout;
  pending_->callback = std::move(callback);
  // A scope approval keeps the signed-in state; observers still hear of it.
  SetState(adds_scopes ? state_ : State::kWaitingForApproval);
  PollRelay();
}

void PubkySessionService::CancelSignIn() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (pending_) {
    FinishSignIn(SignInResult::kCancelled);
  }
}

void PubkySessionService::SignOut() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (pending_) {
    FinishSignIn(SignInResult::kCancelled);
  }
  refresh_timer_.Stop();
  loader_.reset();
  profile_loader_.reset();
  display_name_.reset();
  refreshing_ = false;
  if (session_) {
    // The PoP key is deleted below, so even an unrevoked grant is unusable.
    SendLogout(url_loader_factory_);
  }
  session_.reset();
  DeleteStoredSession();
  SetState(State::kSignedOut);
  RunBearerCallbacks();
  CancelScopeRefreshes();
}

void PubkySessionService::GetBearer(BearerCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ != State::kSignedIn || !session_) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  const base::Time expires_at = base::Time::FromTimeT(
      static_cast<time_t>(session_->token_expires_at));
  if (base::Time::Now() + config_.refresh_margin < expires_at) {
    std::move(callback).Run(session_->bearer);
    return;
  }
  bearer_callbacks_.push_back(std::move(callback));
  Refresh();
}

void PubkySessionService::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void PubkySessionService::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

const SigninGrantRequest* PubkySessionService::pending_request_for_testing()
    const {
  return pending_ ? &pending_->request : nullptr;
}

void PubkySessionService::SignInForTesting(
    StoredSession session,
    std::optional<std::string> display_name) {
  session_ = std::move(session);
  display_name_ = std::move(display_name);
  SetState(State::kSignedIn);
}

void PubkySessionService::OnEncryptorReady(
    scoped_refptr<os_crypt_async::Encryptor> encryptor) {
  encryptor_ = std::move(encryptor);
  file_task_runner_->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(&ReadStoredFile, storage_path_),
      base::BindOnce(&PubkySessionService::OnStoredDataRead,
                     weak_factory_.GetWeakPtr()));
}

void PubkySessionService::OnStoredDataRead(std::optional<std::string> data) {
  if (state_ != State::kLoading) {
    return;
  }
  std::string plaintext;
  if (data && encryptor_ && encryptor_->DecryptString(*data, &plaintext)) {
    session_ = ParseStoredSession(plaintext);
  }
  if (!session_) {
    SetState(State::kSignedOut);
    return;
  }
  RemoveExpiredScopeGrants();
  const base::Time grant_expires_at = base::Time::FromTimeT(
      static_cast<time_t>(session_->grant_expires_at));
  SetState(base::Time::Now() >= grant_expires_at ? State::kApprovalExpired
                                                 : State::kSignedIn);
  ScheduleRefresh();
  FetchProfile();
}

void PubkySessionService::SetState(State state) {
  state_ = state;
  for (Observer& observer : observers_) {
    observer.OnPubkySessionChanged();
  }
}

void PubkySessionService::PollRelay() {
  const base::TimeDelta remaining = pending_->deadline - base::TimeTicks::Now();
  if (!remaining.is_positive()) {
    FinishSignIn(SignInResult::kTimedOut);
    return;
  }
  network::SimpleURLLoader* loader =
      (pending_->loader = CreateLoader(GURL(RelayChannelUrl(pending_->request)),
                                       "GET", kRelayTrafficAnnotation))
          .get();
  loader->SetAllowHttpErrorResults(true);
  loader->SetTimeoutDuration(std::min(config_.relay_poll_timeout, remaining));
  loader->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnRelayResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxRelayMessageSize);
}

void PubkySessionService::OnRelayResponse(std::optional<std::string> body) {
  const int status = ResponseCode(*pending_->loader);
  const int net_error = pending_->loader->NetError();
  pending_->loader.reset();

  if (status == net::HTTP_OK && body) {
    AcknowledgeRelay(RelayChannelUrl(pending_->request));
    base::expected<GrantApproval, ApprovalError> approval =
        OpenApproval(pending_->request, *body, std::nullopt);
    if (!approval.has_value()) {
      FinishSignIn(SignInResult::kRejected);
      return;
    }
    pending_->approval = std::move(approval.value());
    if (pending_->adds_scopes) {
      // A scope grant extends this session, so it must come from this user.
      if (pending_->approval->claims.issuer != session_->user) {
        FinishSignIn(SignInResult::kRejected);
        return;
      }
      pending_->homeserver = session_->homeserver;
      ExchangeGrant();
      return;
    }
    FetchHomeserverRecord();
    return;
  }
  // No approval yet: the relay's own long-poll window or ours ran out.
  if (status == net::HTTP_REQUEST_TIMEOUT || net_error == net::ERR_TIMED_OUT) {
    pending_->consecutive_failures = 0;
    PollRelay();
    return;
  }
  RetryRelayAfterError();
}

void PubkySessionService::RetryRelayAfterError() {
  if (++pending_->consecutive_failures >= kMaxRelayFailures) {
    FinishSignIn(SignInResult::kNetworkError);
    return;
  }
  pending_->retry_timer.Start(FROM_HERE, kRelayRetryDelay,
                              base::BindOnce(&PubkySessionService::PollRelay,
                                             base::Unretained(this)));
}

void PubkySessionService::AcknowledgeRelay(const std::string& channel_url) {
  SendDetached(url_loader_factory_.get(),
               CreateLoader(GURL(channel_url), "DELETE",
                            kRelayTrafficAnnotation));
}

void PubkySessionService::FetchHomeserverRecord() {
  if (pending_->relay_index >= config_.pkarr_relays.size()) {
    FinishSignIn(SignInResult::kHomeserverNotFound);
    return;
  }
  std::string url = config_.pkarr_relays[pending_->relay_index];
  if (!url.ends_with('/')) {
    url.push_back('/');
  }
  url.append(EncodeZ32(pending_->approval->claims.issuer));
  pending_->loader = CreateLoader(GURL(url), "GET", kPkarrTrafficAnnotation);
  pending_->loader->SetTimeoutDuration(kRequestTimeout);
  pending_->loader->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnHomeserverRecord,
                     weak_factory_.GetWeakPtr()),
      kMaxRelayPayloadSize);
}

void PubkySessionService::OnHomeserverRecord(std::optional<std::string> body) {
  pending_->loader.reset();
  const Key& user = pending_->approval->claims.issuer;
  std::optional<SignedPacket> packet =
      body ? VerifyRelayPayload(user, *body) : std::nullopt;
  std::optional<Key> homeserver =
      packet ? FindHomeserver(user, packet->dns_packet) : std::nullopt;
  if (!homeserver) {
    ++pending_->relay_index;
    FetchHomeserverRecord();
    return;
  }
  pending_->homeserver = *homeserver;
  ExchangeGrant();
}

void PubkySessionService::ExchangeGrant() {
  const GrantApproval& approval = *pending_->approval;
  network::SimpleURLLoader* loader =
      (pending_->loader = CreateLoader(GrantSessionUrl(pending_->homeserver),
                                       "POST", kHomeserverTrafficAnnotation))
          .get();
  loader->AttachStringForUpload(
      CreateGrantSessionRequestBody(
          approval.grant_jws,
          CreatePopProof(pending_->client_seed, pending_->homeserver,
                         approval.claims.grant_id, base::Time::Now())),
      "application/json");
  loader->SetTimeoutDuration(kRequestTimeout);
  loader->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnExchangeResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxSessionResponseSize);
}

void PubkySessionService::OnExchangeResponse(std::optional<std::string> body) {
  pending_->loader.reset();
  std::optional<GrantSession> response =
      body ? ParseGrantSessionResponse(*body) : std::nullopt;
  GrantApproval& approval = *pending_->approval;
  if (!response || response->user != approval.claims.issuer ||
      response->homeserver != pending_->homeserver ||
      response->grant_id != approval.claims.grant_id) {
    FinishSignIn(SignInResult::kExchangeFailed);
    return;
  }
  if (pending_->adds_scopes) {
    ScopeGrant grant;
    grant.grant_jws = approval.grant_jws;
    grant.grant_id = approval.claims.grant_id;
    grant.capabilities = response->capabilities;
    grant.bearer = response->token;
    grant.token_expires_at = response->token_expires_at;
    grant.grant_expires_at = response->grant_expires_at;
    session_->scope_grants.push_back(std::move(grant));
    Persist();
    FinishSignIn(SignInResult::kSignedIn);
    return;
  }
  StoredSession session;
  session.client_seed = pending_->client_seed;
  session.grant_jws = approval.grant_jws;
  session.user = approval.claims.issuer;
  session.homeserver = pending_->homeserver;
  session.grant_id = approval.claims.grant_id;
  session.capabilities = response->capabilities;
  session.bearer = response->token;
  session.token_expires_at = response->token_expires_at;
  session.grant_expires_at = response->grant_expires_at;
  session.encryption_keys = std::move(approval.encryption_keys);
  session_ = std::move(session);
  Persist();
  FinishSignIn(SignInResult::kSignedIn);
}

void PubkySessionService::FinishSignIn(SignInResult result) {
  SignInCallback callback = std::move(pending_->callback);
  const State previous_state = pending_->previous_state;
  const bool adds_scopes = pending_->adds_scopes;
  pending_.reset();
  if (adds_scopes) {
    SetState(state_);
  } else {
    last_sign_in_result_ = result;
    if (result == SignInResult::kSignedIn) {
      SetState(State::kSignedIn);
      ScheduleRefresh();
      FetchProfile();
    } else {
      SetState(previous_state);
    }
  }
  std::move(callback).Run(result);
}

void PubkySessionService::ScheduleRefresh() {
  refresh_timer_.Stop();
  if (state_ != State::kSignedIn || !session_) {
    return;
  }
  const base::Time refresh_at =
      base::Time::FromTimeT(static_cast<time_t>(session_->token_expires_at)) -
      config_.refresh_margin;
  refresh_timer_.Start(
      FROM_HERE, std::max(base::TimeDelta(), refresh_at - base::Time::Now()),
      base::BindOnce(&PubkySessionService::Refresh, base::Unretained(this)));
}

void PubkySessionService::Refresh() {
  if (refreshing_) {
    return;
  }
  if (state_ != State::kSignedIn || !session_) {
    RunBearerCallbacks();
    return;
  }
  const base::Time grant_expires_at =
      base::Time::FromTimeT(static_cast<time_t>(session_->grant_expires_at));
  if (base::Time::Now() >= grant_expires_at) {
    SetState(State::kApprovalExpired);
    RunBearerCallbacks();
    return;
  }
  refreshing_ = true;
  loader_ = CreateLoader(GrantSessionUrl(session_->homeserver), "POST",
                         kHomeserverTrafficAnnotation);
  loader_->SetAllowHttpErrorResults(true);
  loader_->AttachStringForUpload(
      CreateGrantSessionRequestBody(
          session_->grant_jws,
          CreatePopProof(session_->client_seed, session_->homeserver,
                         session_->grant_id, base::Time::Now())),
      "application/json");
  loader_->SetTimeoutDuration(kRequestTimeout);
  loader_->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnRefreshResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxSessionResponseSize);
}

void PubkySessionService::OnRefreshResponse(std::optional<std::string> body) {
  const int status = ResponseCode(*loader_);
  loader_.reset();
  refreshing_ = false;

  std::optional<GrantSession> response =
      status >= 200 && status < 300 && body ? ParseGrantSessionResponse(*body)
                                            : std::nullopt;
  if (response && response->grant_id == session_->grant_id) {
    session_->bearer = response->token;
    session_->token_expires_at = response->token_expires_at;
    session_->grant_expires_at = response->grant_expires_at;
    Persist();
    ScheduleRefresh();
    RunBearerCallbacks();
    return;
  }
  if (status == net::HTTP_UNAUTHORIZED || status == net::HTTP_FORBIDDEN) {
    refresh_timer_.Stop();
    SetState(State::kApprovalExpired);
    RunBearerCallbacks();
    return;
  }
  // A network or server error: keep the session and try again soon. Callers
  // still get the current bearer while it is valid.
  refresh_timer_.Start(
      FROM_HERE, kRefreshRetryDelay,
      base::BindOnce(&PubkySessionService::Refresh, base::Unretained(this)));
  RunBearerCallbacks();
}

void PubkySessionService::RunBearerCallbacks() {
  std::vector<BearerCallback> callbacks;
  callbacks.swap(bearer_callbacks_);
  std::optional<std::string> bearer;
  if (state_ == State::kSignedIn && session_ &&
      base::Time::Now() < base::Time::FromTimeT(
                              static_cast<time_t>(session_->token_expires_at))) {
    bearer = session_->bearer;
  }
  for (BearerCallback& callback : callbacks) {
    std::move(callback).Run(bearer);
  }
}

void PubkySessionService::GetBearerFor(const Capability& needed,
                                       BearerCallback callback) {
  if (!session_) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  if (CapabilitiesCover(session_->capabilities, needed)) {
    GetBearer(std::move(callback));
    return;
  }
  RemoveExpiredScopeGrants();
  for (const ScopeGrant& grant : session_->scope_grants) {
    if (!CapabilitiesCover(grant.capabilities, needed)) {
      continue;
    }
    const base::Time expires_at =
        base::Time::FromTimeT(static_cast<time_t>(grant.token_expires_at));
    if (base::Time::Now() + config_.refresh_margin < expires_at) {
      std::move(callback).Run(grant.bearer);
      return;
    }
    RefreshScopeGrant(grant.grant_id, std::move(callback));
    return;
  }
  std::move(callback).Run(std::nullopt);
}

ScopeGrant* PubkySessionService::FindScopeGrant(const std::string& grant_id) {
  if (!session_) {
    return nullptr;
  }
  auto it = std::ranges::find(session_->scope_grants, grant_id,
                              &ScopeGrant::grant_id);
  return it == session_->scope_grants.end() ? nullptr : &*it;
}

void PubkySessionService::RemoveExpiredScopeGrants() {
  if (std::erase_if(session_->scope_grants, [](const ScopeGrant& grant) {
        return IsExpired(grant.grant_expires_at);
      })) {
    Persist();
  }
}

void PubkySessionService::RefreshScopeGrant(const std::string& grant_id,
                                            BearerCallback callback) {
  ScopeRefresh& refresh = scope_refreshes_[grant_id];
  refresh.callbacks.push_back(std::move(callback));
  if (refresh.loader) {
    return;
  }
  const ScopeGrant& grant = *FindScopeGrant(grant_id);
  refresh.loader = CreateLoader(GrantSessionUrl(session_->homeserver), "POST",
                                kHomeserverTrafficAnnotation);
  refresh.loader->SetAllowHttpErrorResults(true);
  refresh.loader->AttachStringForUpload(
      CreateGrantSessionRequestBody(
          grant.grant_jws,
          CreatePopProof(session_->client_seed, session_->homeserver,
                         grant.grant_id, base::Time::Now())),
      "application/json");
  refresh.loader->SetTimeoutDuration(kRequestTimeout);
  refresh.loader->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnScopeRefreshResponse,
                     weak_factory_.GetWeakPtr(), grant_id),
      kMaxSessionResponseSize);
}

void PubkySessionService::OnScopeRefreshResponse(
    const std::string& grant_id,
    std::optional<std::string> body) {
  auto it = scope_refreshes_.find(grant_id);
  const int status = ResponseCode(*it->second.loader);
  std::vector<BearerCallback> callbacks = std::move(it->second.callbacks);
  scope_refreshes_.erase(it);

  std::optional<GrantSession> response =
      status >= 200 && status < 300 && body ? ParseGrantSessionResponse(*body)
                                            : std::nullopt;
  std::optional<std::string> bearer;
  if (ScopeGrant* grant = FindScopeGrant(grant_id)) {
    if (response && response->grant_id == grant_id) {
      grant->bearer = response->token;
      grant->token_expires_at = response->token_expires_at;
      grant->grant_expires_at = response->grant_expires_at;
      Persist();
      bearer = grant->bearer;
    } else if (status == net::HTTP_UNAUTHORIZED ||
               status == net::HTTP_FORBIDDEN) {
      // Revoked or expired on the homeserver: the scope needs a new approval.
      std::erase_if(session_->scope_grants, [&](const ScopeGrant& entry) {
        return entry.grant_id == grant_id;
      });
      Persist();
      SetState(state_);
    } else if (!IsExpired(grant->token_expires_at)) {
      bearer = grant->bearer;
    }
  }
  for (BearerCallback& callback : callbacks) {
    std::move(callback).Run(bearer);
  }
}

void PubkySessionService::CancelScopeRefreshes() {
  std::map<std::string, ScopeRefresh> refreshes;
  refreshes.swap(scope_refreshes_);
  for (auto& [grant_id, refresh] : refreshes) {
    for (BearerCallback& callback : refresh.callbacks) {
      std::move(callback).Run(std::nullopt);
    }
  }
}

void PubkySessionService::SendStorageRequest(StorageRequest request,
                                             StorageCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  Capability needed;
  needed.scope = request.path;
  needed.read = !IsWrite(request.method);
  needed.write = IsWrite(request.method);
  GetBearerFor(needed,
               base::BindOnce(&PubkySessionService::StartStorageRequest,
                              weak_factory_.GetWeakPtr(), std::move(request),
                              std::move(callback)));
}

void PubkySessionService::StartStorageRequest(
    StorageRequest request,
    StorageCallback callback,
    std::optional<std::string> bearer) {
  StorageResponse failure;
  failure.status = StorageStatus::kNotSignedIn;
  // Public data is readable without a bearer, so reads keep working while the
  // approval is expired.
  const bool public_read =
      !IsWrite(request.method) && request.path.starts_with("/pub/");
  if (!session_ || (!bearer && !public_read)) {
    std::move(callback).Run(std::move(failure));
    return;
  }
  if (request.body.size() > kMaxStorageBodySize) {
    failure.status = StorageStatus::kTooLarge;
    std::move(callback).Run(std::move(failure));
    return;
  }
  std::unique_ptr<network::SimpleURLLoader> loader = CreateLoader(
      StorageUrl(session_->homeserver, session_->user, request),
      HttpMethod(request.method), kStorageTrafficAnnotation,
      bearer ? &*bearer : nullptr);
  if (request.method == StorageMethod::kPut) {
    loader->AttachStringForUpload(request.body,
                                  request.content_type.empty()
                                      ? "application/octet-stream"
                                      : request.content_type);
  }
  loader->SetAllowHttpErrorResults(true);
  loader->SetTimeoutDuration(kRequestTimeout);
  const int loader_id = next_storage_loader_id_++;
  network::SimpleURLLoader* raw = loader.get();
  storage_loaders_[loader_id] = std::move(loader);
  raw->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnStorageResponse,
                     weak_factory_.GetWeakPtr(), loader_id,
                     std::move(callback)),
      kMaxStorageBodySize);
}

void PubkySessionService::OnStorageResponse(int loader_id,
                                            StorageCallback callback,
                                            std::optional<std::string> body) {
  std::unique_ptr<network::SimpleURLLoader> loader =
      std::move(storage_loaders_[loader_id]);
  storage_loaders_.erase(loader_id);
  const int status = ResponseCode(*loader);

  StorageResponse response;
  if (loader->NetError() == net::ERR_INSUFFICIENT_RESOURCES) {
    response.status = StorageStatus::kTooLarge;
  } else if (status >= 200 && status < 300 && body) {
    response.status = StorageStatus::kOk;
    response.body = std::move(*body);
    const network::mojom::URLResponseHead* head = loader->ResponseInfo();
    response.content_type = head->mime_type;
    if (!head->charset.empty()) {
      response.content_type += "; charset=" + head->charset;
    }
  } else if (status == net::HTTP_NOT_FOUND) {
    response.status = StorageStatus::kNotFound;
  } else if (status == net::HTTP_UNAUTHORIZED ||
             status == net::HTTP_FORBIDDEN) {
    response.status = StorageStatus::kForbidden;
  } else {
    response.status = StorageStatus::kNetworkError;
  }
  std::move(callback).Run(std::move(response));
}

void PubkySessionService::FetchProfile() {
  if (!session_) {
    return;
  }
  const GURL url("https://" + EncodeZ32(session_->homeserver) + "/storage/" +
                 EncodeZ32(session_->user) + "/pub/pubky.app/profile.json");
  profile_loader_ = CreateLoader(url, "GET", kProfileTrafficAnnotation);
  profile_loader_->SetTimeoutDuration(kRequestTimeout);
  profile_loader_->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnProfileResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxProfileSize);
}

void PubkySessionService::OnProfileResponse(std::optional<std::string> body) {
  profile_loader_.reset();
  std::optional<std::string> name =
      body ? ParseProfileName(*body) : std::nullopt;
  if (name == display_name_) {
    return;
  }
  display_name_ = std::move(name);
  SetState(state_);
}

void PubkySessionService::Persist() {
  if (storage_path_.empty() || !encryptor_ || !session_) {
    return;
  }
  std::string ciphertext;
  if (!encryptor_->EncryptString(SerializeStoredSession(*session_),
                                 &ciphertext)) {
    return;
  }
  file_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&WriteStoredFile, storage_path_, std::move(ciphertext)));
}

void PubkySessionService::DeleteStoredSession() {
  if (storage_path_.empty()) {
    return;
  }
  file_task_runner_->PostTask(FROM_HERE,
                              base::GetDeleteFileCallback(storage_path_));
}

void PubkySessionService::SendLogout(
    scoped_refptr<network::SharedURLLoaderFactory> factory) {
  std::vector<std::pair<std::string, std::string>> grants = {
      {session_->grant_jws, session_->grant_id}};
  for (const ScopeGrant& grant : session_->scope_grants) {
    grants.emplace_back(grant.grant_jws, grant.grant_id);
  }
  for (const auto& [grant_jws, grant_id] : grants) {
    std::unique_ptr<network::SimpleURLLoader> loader =
        CreateLoader(GrantSessionUrl(session_->homeserver), "DELETE",
                     kHomeserverTrafficAnnotation);
    loader->AttachStringForUpload(
        CreateGrantSessionRequestBody(
            grant_jws, CreatePopProof(session_->client_seed,
                                      session_->homeserver, grant_id,
                                      base::Time::Now())),
        "application/json");
    SendDetached(factory.get(), std::move(loader));
  }
}

}  // namespace pubky_session

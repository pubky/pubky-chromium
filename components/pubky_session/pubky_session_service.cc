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
#include "base/strings/string_util.h"
#include "base/values.h"
#include "base/task/thread_pool.h"
#include "components/os_crypt/async/browser/os_crypt_async.h"
#include "components/os_crypt/async/common/encryptor.h"
#include "components/pubky_session/core/grant_session.h"
#include "components/pubky_session/core/pkarr_packet.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
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
          type: ACCESS_TOKENS
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
    const net::NetworkTrafficAnnotationTag& annotation) {
  auto request = std::make_unique<network::ResourceRequest>();
  request->url = url;
  request->method = method;
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
};

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
  retry_timer_.Stop();
  loader_.reset();
  profile_loader_.reset();
  pending_.reset();
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
  return pending_ ? pending_->link : std::string();
}

std::optional<Key> PubkySessionService::user() const {
  return session_ ? std::optional<Key>(session_->user) : std::nullopt;
}

std::optional<Key> PubkySessionService::homeserver() const {
  return session_ ? std::optional<Key>(session_->homeserver) : std::nullopt;
}

std::vector<Capability> PubkySessionService::capabilities() const {
  return session_ ? session_->capabilities : std::vector<Capability>();
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
  last_sign_in_result_.reset();
  pending_ = std::make_unique<PendingSignIn>();
  pending_->previous_state = state_;
  pending_->client_seed = RandomKey();
  pending_->request.capabilities = *ParseCapabilities(kSignInCapabilities);
  pending_->request.relay = config_.relay_inbox;
  pending_->request.client_public_key = Ed25519PublicKey(pending_->client_seed);
  pending_->request.format = ApprovalFormat::kBareGrant;
  pending_->request.channel_key = RandomKey();
  pending_->link = BuildSigninGrantLink(pending_->request);
  pending_->deadline = base::TimeTicks::Now() + config_.sign_in_timeout;
  pending_->callback = std::move(callback);
  SetState(State::kWaitingForApproval);
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
  loader_ = CreateLoader(GURL(RelayChannelUrl(pending_->request)), "GET",
                         kRelayTrafficAnnotation);
  loader_->SetAllowHttpErrorResults(true);
  loader_->SetTimeoutDuration(std::min(config_.relay_poll_timeout, remaining));
  loader_->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnRelayResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxRelayMessageSize);
}

void PubkySessionService::OnRelayResponse(std::optional<std::string> body) {
  const int status = ResponseCode(*loader_);
  const int net_error = loader_->NetError();
  loader_.reset();

  if (status == net::HTTP_OK && body) {
    AcknowledgeRelay(RelayChannelUrl(pending_->request));
    base::expected<GrantApproval, ApprovalError> approval =
        OpenApproval(pending_->request, *body, std::nullopt);
    if (!approval.has_value()) {
      FinishSignIn(SignInResult::kRejected);
      return;
    }
    pending_->approval = std::move(approval.value());
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
  retry_timer_.Start(FROM_HERE, kRelayRetryDelay,
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
  loader_ = CreateLoader(GURL(url), "GET", kPkarrTrafficAnnotation);
  loader_->SetTimeoutDuration(kRequestTimeout);
  loader_->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnHomeserverRecord,
                     weak_factory_.GetWeakPtr()),
      kMaxRelayPayloadSize);
}

void PubkySessionService::OnHomeserverRecord(std::optional<std::string> body) {
  loader_.reset();
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
  loader_ = CreateLoader(GrantSessionUrl(pending_->homeserver), "POST",
                         kHomeserverTrafficAnnotation);
  loader_->AttachStringForUpload(
      CreateGrantSessionRequestBody(
          approval.grant_jws,
          CreatePopProof(pending_->client_seed, pending_->homeserver,
                         approval.claims.grant_id, base::Time::Now())),
      "application/json");
  loader_->SetTimeoutDuration(kRequestTimeout);
  loader_->DownloadToString(
      url_loader_factory_.get(),
      base::BindOnce(&PubkySessionService::OnExchangeResponse,
                     weak_factory_.GetWeakPtr()),
      kMaxSessionResponseSize);
}

void PubkySessionService::OnExchangeResponse(std::optional<std::string> body) {
  loader_.reset();
  std::optional<GrantSession> response =
      body ? ParseGrantSessionResponse(*body) : std::nullopt;
  GrantApproval& approval = *pending_->approval;
  if (!response || response->user != approval.claims.issuer ||
      response->homeserver != pending_->homeserver ||
      response->grant_id != approval.claims.grant_id) {
    FinishSignIn(SignInResult::kExchangeFailed);
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
  retry_timer_.Stop();
  loader_.reset();
  SignInCallback callback = std::move(pending_->callback);
  const State previous_state = pending_->previous_state;
  pending_.reset();
  last_sign_in_result_ = result;
  if (result == SignInResult::kSignedIn) {
    SetState(State::kSignedIn);
    ScheduleRefresh();
    FetchProfile();
  } else {
    SetState(previous_state);
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
  std::unique_ptr<network::SimpleURLLoader> loader =
      CreateLoader(GrantSessionUrl(session_->homeserver), "DELETE",
                   kHomeserverTrafficAnnotation);
  loader->AttachStringForUpload(
      CreateGrantSessionRequestBody(
          session_->grant_jws,
          CreatePopProof(session_->client_seed, session_->homeserver,
                         session_->grant_id, base::Time::Now())),
      "application/json");
  SendDetached(factory.get(), std::move(loader));
}

}  // namespace pubky_session

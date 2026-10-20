// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/pubky_session/pubky_session_host_impl.h"

#include <algorithm>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "base/strings/string_split.h"
#include "base/strings/string_view_util.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "components/pubky_session/core/crypto.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "mojo/public/cpp/base/big_buffer.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "url/origin.h"

namespace {

using blink::mojom::PubkyStatus;
using pubky_session::Capability;
using pubky_session::PubkySessionService;
using StorageStatus = PubkySessionService::StorageStatus;

// The sign-in link stays valid for five minutes; this leaves time to open the
// panel first.
constexpr base::TimeDelta kSignInWait = base::Minutes(6);

PubkySessionHostImpl::Ui* g_ui = nullptr;
PubkySessionHostImpl::Ui* g_ui_for_testing = nullptr;

PubkySessionHostImpl::Ui* GetUi() {
  return g_ui_for_testing ? g_ui_for_testing : g_ui;
}

PubkyStatus ToMojo(StorageStatus status) {
  switch (status) {
    case StorageStatus::kOk:
      return PubkyStatus::kOk;
    case StorageStatus::kNotFound:
      return PubkyStatus::kNotFound;
    // A refused bearer means the browser's approval no longer holds.
    case StorageStatus::kNotSignedIn:
    case StorageStatus::kForbidden:
      return PubkyStatus::kNotSignedIn;
    case StorageStatus::kTooLarge:
      return PubkyStatus::kTooLarge;
    case StorageStatus::kNetworkError:
      return PubkyStatus::kNetworkError;
  }
  NOTREACHED();
}

// The entries of `scopes` that `granted` does not cover yet.
std::vector<Capability> Uncovered(const std::vector<Capability>& granted,
                                  const std::vector<Capability>& scopes) {
  std::vector<Capability> missing;
  for (const Capability& scope : scopes) {
    if (!pubky_session::CapabilitiesCover(granted, scope)) {
      missing.push_back(scope);
    }
  }
  return missing;
}

PubkySessionService::StorageRequest MakeRequest(
    PubkySessionService::StorageMethod method,
    const std::string& path) {
  PubkySessionService::StorageRequest request;
  request.method = method;
  request.path = path;
  return request;
}

void OnGetResponse(PubkySessionHostImpl::GetCallback callback,
                   PubkySessionService::StorageResponse response) {
  if (response.status != StorageStatus::kOk) {
    std::move(callback).Run(ToMojo(response.status), std::string(),
                            std::nullopt);
    return;
  }
  std::move(callback).Run(PubkyStatus::kOk, response.content_type,
                          mojo_base::BigBuffer(base::as_byte_span(response.body)));
}

void OnStatusResponse(base::OnceCallback<void(PubkyStatus)> callback,
                      PubkySessionService::StorageResponse response) {
  std::move(callback).Run(ToMojo(response.status));
}

void OnListResponse(PubkySessionHostImpl::ListCallback callback,
                    PubkySessionService::StorageResponse response) {
  if (response.status != StorageStatus::kOk) {
    std::move(callback).Run(ToMojo(response.status), {});
    return;
  }
  std::move(callback).Run(
      PubkyStatus::kOk,
      base::SplitString(response.body, "\n", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY));
}

}  // namespace

PubkySessionHostImpl::PendingRequest::PendingRequest() = default;
PubkySessionHostImpl::PendingRequest::~PendingRequest() = default;

// static
void PubkySessionHostImpl::Create(
    content::RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<blink::mojom::PubkySessionHost> receiver) {
  Profile* profile =
      Profile::FromBrowserContext(render_frame_host->GetBrowserContext());
  // Owned by the document: deleted when it goes away or the page disconnects.
  new PubkySessionHostImpl(
      *render_frame_host, std::move(receiver),
      PubkySessionServiceFactory::GetForProfile(profile),
      HostContentSettingsMapFactory::GetForProfile(profile));
}

// static
void PubkySessionHostImpl::SetUi(Ui* ui) {
  g_ui = ui;
}

// static
void PubkySessionHostImpl::SetUiForTesting(Ui* ui) {
  g_ui_for_testing = ui;
}

PubkySessionHostImpl::PubkySessionHostImpl(
    content::RenderFrameHost& render_frame_host,
    mojo::PendingReceiver<blink::mojom::PubkySessionHost> receiver,
    pubky_session::PubkySessionService* service,
    HostContentSettingsMap* settings)
    : DocumentService(render_frame_host, std::move(receiver)),
      service_(service),
      settings_(settings) {
  if (service_) {
    observation_.Observe(service_.get());
  }
}

PubkySessionHostImpl::~PubkySessionHostImpl() = default;

void PubkySessionHostImpl::RequestSession(
    const std::vector<std::string>& scopes,
    RequestSessionCallback callback) {
  if (!IsEligible() || request_in_progress_) {
    std::move(callback).Run(PubkyStatus::kNotAllowed, std::string());
    return;
  }
  std::vector<Capability> parsed;
  for (const std::string& text : scopes) {
    std::optional<Capability> capability = pubky_session::ParseCapability(text);
    if (!capability ||
        !(capability->read || capability->write ||
          capability->encryption_keys)) {
      std::move(callback).Run(PubkyStatus::kInvalidArgument, std::string());
      return;
    }
    parsed.push_back(*capability);
  }
  if (parsed.empty()) {
    std::move(callback).Run(PubkyStatus::kInvalidArgument, std::string());
    return;
  }
  // Scoped encryption keys wait for their own design.
  if (std::ranges::any_of(parsed, &Capability::encryption_keys)) {
    std::move(callback).Run(PubkyStatus::kNotSupported, std::string());
    return;
  }
  request_in_progress_ = true;
  pending_ = std::make_unique<PendingRequest>();
  pending_->scopes = std::move(parsed);
  pending_->callback = std::move(callback).Then(base::BindOnce(
      &PubkySessionHostImpl::OnRequestDone, weak_factory_.GetWeakPtr()));
  sign_in_timer_.Start(
      FROM_HERE, kSignInWait,
      base::BindOnce(&PubkySessionHostImpl::FailRequest, base::Unretained(this),
                     PubkyStatus::kNotSignedIn));
  AdvanceRequest();
}

void PubkySessionHostImpl::Get(const std::string& path, GetCallback callback) {
  const PubkyStatus status =
      CheckAccess(path, /*write=*/false, /*directory=*/false);
  if (status != PubkyStatus::kOk) {
    std::move(callback).Run(status, std::string(), std::nullopt);
    return;
  }
  service_->SendStorageRequest(
      MakeRequest(PubkySessionService::StorageMethod::kGet, path),
      base::BindOnce(&OnGetResponse, std::move(callback)));
}

void PubkySessionHostImpl::Put(const std::string& path,
                               mojo_base::BigBuffer body,
                               const std::string& content_type,
                               PutCallback callback) {
  const PubkyStatus status =
      CheckAccess(path, /*write=*/true, /*directory=*/false);
  if (status != PubkyStatus::kOk) {
    std::move(callback).Run(status);
    return;
  }
  PubkySessionService::StorageRequest request =
      MakeRequest(PubkySessionService::StorageMethod::kPut, path);
  request.body =
      std::string(base::as_string_view(base::span<const uint8_t>(body)));
  request.content_type = content_type;
  service_->SendStorageRequest(
      std::move(request),
      base::BindOnce(&OnStatusResponse, std::move(callback)));
}

void PubkySessionHostImpl::Delete(const std::string& path,
                                  DeleteCallback callback) {
  const PubkyStatus status =
      CheckAccess(path, /*write=*/true, /*directory=*/false);
  if (status != PubkyStatus::kOk) {
    std::move(callback).Run(status);
    return;
  }
  service_->SendStorageRequest(
      MakeRequest(PubkySessionService::StorageMethod::kDelete, path),
      base::BindOnce(&OnStatusResponse, std::move(callback)));
}

void PubkySessionHostImpl::List(const std::string& path,
                                blink::mojom::PubkyListOptionsPtr options,
                                ListCallback callback) {
  const PubkyStatus status =
      CheckAccess(path, /*write=*/false, /*directory=*/true);
  if (status != PubkyStatus::kOk) {
    std::move(callback).Run(status, {});
    return;
  }
  PubkySessionService::StorageRequest request =
      MakeRequest(PubkySessionService::StorageMethod::kList, path);
  if (options->limit) {
    request.limit = options->limit;
  }
  request.cursor = options->cursor;
  request.shallow = options->shallow;
  request.reverse = options->reverse;
  service_->SendStorageRequest(
      std::move(request), base::BindOnce(&OnListResponse, std::move(callback)));
}

void PubkySessionHostImpl::OnPubkySessionChanged() {
  AdvanceRequest();
}

bool PubkySessionHostImpl::IsEligible() {
  const url::Origin& document_origin = origin();
  if (!service_ || document_origin.opaque() ||
      !network::IsOriginPotentiallyTrustworthy(document_origin) ||
      render_frame_host().IsNestedWithinFencedFrame()) {
    return false;
  }
  // Same-origin iframes may use the identity; a frame anywhere below another
  // origin may not.
  for (content::RenderFrameHost* frame = render_frame_host().GetParent();
       frame; frame = frame->GetParent()) {
    if (!frame->GetLastCommittedOrigin().IsSameOriginWith(document_origin)) {
      return false;
    }
  }
  return true;
}

content::WebContents* PubkySessionHostImpl::web_contents() {
  return content::WebContents::FromRenderFrameHost(&render_frame_host());
}

void PubkySessionHostImpl::AdvanceRequest() {
  if (!pending_) {
    return;
  }
  switch (service_->state()) {
    case PubkySessionService::State::kLoading:
      return;
    case PubkySessionService::State::kWaitingForApproval:
      pending_->sign_in_started = true;
      return;
    case PubkySessionService::State::kSignedOut:
      if (pending_->sign_in_started) {
        // The user cancelled the sign-in, or its link expired.
        FailRequest(PubkyStatus::kNotSignedIn);
        return;
      }
      if (!pending_->opened_sign_in) {
        pending_->opened_sign_in = true;
        Ui* ui = GetUi();
        if (!ui) {
          FailRequest(PubkyStatus::kNotSignedIn);
          return;
        }
        // Opening the panel may start the sign-in, and re-enter this method.
        ui->OpenSignIn(web_contents());
      }
      return;
    case PubkySessionService::State::kSignedIn:
    case PubkySessionService::State::kApprovalExpired: {
      sign_in_timer_.Stop();
      std::unique_ptr<PendingRequest> request = std::move(pending_);
      ContinueRequest(std::move(request->scopes), std::move(request->callback));
      return;
    }
  }
}

void PubkySessionHostImpl::FailRequest(PubkyStatus status) {
  sign_in_timer_.Stop();
  std::unique_ptr<PendingRequest> request = std::move(pending_);
  std::move(request->callback).Run(status, std::string());
}

void PubkySessionHostImpl::OnRequestDone() {
  request_in_progress_ = false;
}

void PubkySessionHostImpl::ContinueRequest(std::vector<Capability> scopes,
                                           RequestSessionCallback callback) {
  const pubky_session::Key user = *service_->user();
  std::vector<Capability> missing = Uncovered(
      pubky_session::GetSiteScopes(settings_, origin(), user), scopes);
  if (missing.empty()) {
    std::move(callback).Run(PubkyStatus::kOk, pubky_session::EncodeZ32(user));
    return;
  }
  Ui* ui = GetUi();
  if (!ui) {
    std::move(callback).Run(PubkyStatus::kNotAllowed, std::string());
    return;
  }
  // Only the scopes the site does not have yet are asked for.
  ui->RequestAccess(
      web_contents(), origin(), missing,
      base::BindOnce(&PubkySessionHostImpl::OnAccessDecision,
                     weak_factory_.GetWeakPtr(), missing, std::move(callback)));
}

void PubkySessionHostImpl::OnAccessDecision(std::vector<Capability> scopes,
                                            RequestSessionCallback callback,
                                            bool allowed) {
  if (!allowed || !service_->user()) {
    std::move(callback).Run(PubkyStatus::kNotAllowed, std::string());
    return;
  }
  // Scopes outside the browser's own approval, such as /priv/ paths, need a
  // Pubky Ring approval for those scopes first.
  std::vector<Capability> unapproved =
      Uncovered(service_->capabilities(), scopes);
  if (unapproved.empty()) {
    Grant(scopes, std::move(callback));
    return;
  }
  service_->RequestScopes(
      std::move(unapproved),
      base::BindOnce(&PubkySessionHostImpl::OnScopesApproved,
                     weak_factory_.GetWeakPtr(), std::move(scopes),
                     std::move(callback)));
}

void PubkySessionHostImpl::OnScopesApproved(
    std::vector<Capability> scopes,
    RequestSessionCallback callback,
    PubkySessionService::SignInResult result) {
  // Ring may approve less than was asked.
  if (result != PubkySessionService::SignInResult::kSignedIn ||
      !Uncovered(service_->capabilities(), scopes).empty()) {
    std::move(callback).Run(PubkyStatus::kNotAllowed, std::string());
    return;
  }
  Grant(scopes, std::move(callback));
}

void PubkySessionHostImpl::Grant(const std::vector<Capability>& scopes,
                                 RequestSessionCallback callback) {
  std::optional<pubky_session::Key> user = service_->user();
  if (!user) {
    std::move(callback).Run(PubkyStatus::kNotSignedIn, std::string());
    return;
  }
  pubky_session::AllowSiteScopes(settings_, origin(), *user, scopes);
  std::move(callback).Run(PubkyStatus::kOk, pubky_session::EncodeZ32(*user));
}

PubkyStatus PubkySessionHostImpl::CheckAccess(const std::string& path,
                                              bool write,
                                              bool directory) {
  if (!IsEligible()) {
    return PubkyStatus::kNotAllowed;
  }
  if (!pubky_session::IsCanonicalStoragePath(path) ||
      path.ends_with('/') != directory) {
    return PubkyStatus::kInvalidArgument;
  }
  std::optional<pubky_session::Key> user = service_->user();
  if (!user) {
    return PubkyStatus::kNotSignedIn;
  }
  Capability needed;
  needed.scope = path;
  needed.read = !write;
  needed.write = write;
  // Read on every call, so a removed site fails at once.
  if (!pubky_session::CapabilitiesCover(
          pubky_session::GetSiteScopes(settings_, origin(), *user), needed)) {
    return PubkyStatus::kNotAllowed;
  }
  return PubkyStatus::kOk;
}

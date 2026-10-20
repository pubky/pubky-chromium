// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_HOST_IMPL_H_
#define CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_HOST_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/scoped_observation.h"
#include "base/timer/timer.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/pubky_session_service.h"
#include "content/public/browser/document_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "third_party/blink/public/mojom/pubky/pubky.mojom.h"

class HostContentSettingsMap;

namespace content {
class RenderFrameHost;
class WebContents;
}  // namespace content

namespace url {
class Origin;
}  // namespace url

// The browser side of navigator.pubky for one document. Sites never see the
// grant or the bearer: this host checks each call against the scopes the user
// allowed for the document's origin, and PubkySessionService makes the call.
// Only secure documents whose ancestors all share their origin may use it.
// See pubky/SESSIONS.md.
class PubkySessionHostImpl final
    : public content::DocumentService<blink::mojom::PubkySessionHost>,
      public pubky_session::PubkySessionService::Observer {
 public:
  // The browser UI the host relies on. The toolbar, which owns the identity
  // panel, provides it.
  class Ui {
   public:
    virtual ~Ui() = default;
    // Opens the identity panel in the window that shows `contents`, which
    // starts sign-in outside Incognito.
    virtual void OpenSignIn(content::WebContents* contents) = 0;
    // Asks whether `origin` may use `scopes` with the user's identity.
    virtual void RequestAccess(
        content::WebContents* contents,
        const url::Origin& origin,
        const std::vector<pubky_session::Capability>& scopes,
        base::OnceCallback<void(bool allowed)> callback) = 0;
  };

  static void Create(
      content::RenderFrameHost* render_frame_host,
      mojo::PendingReceiver<blink::mojom::PubkySessionHost> receiver);

  static void SetUi(Ui* ui);
  // Takes precedence over SetUi() while set.
  static void SetUiForTesting(Ui* ui);

  PubkySessionHostImpl(const PubkySessionHostImpl&) = delete;
  PubkySessionHostImpl& operator=(const PubkySessionHostImpl&) = delete;

  // blink::mojom::PubkySessionHost:
  void RequestSession(const std::vector<std::string>& scopes,
                      RequestSessionCallback callback) override;
  void Get(const std::string& path, GetCallback callback) override;
  void Put(const std::string& path,
           mojo_base::BigBuffer body,
           const std::string& content_type,
           PutCallback callback) override;
  void Delete(const std::string& path, DeleteCallback callback) override;
  void List(const std::string& path,
            blink::mojom::PubkyListOptionsPtr options,
            ListCallback callback) override;

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

 private:
  // A requestSession() call waiting for the browser to sign in.
  struct PendingRequest {
    PendingRequest();
    ~PendingRequest();

    std::vector<pubky_session::Capability> scopes;
    RequestSessionCallback callback;
    bool opened_sign_in = false;
    bool sign_in_started = false;
  };

  PubkySessionHostImpl(
      content::RenderFrameHost& render_frame_host,
      mojo::PendingReceiver<blink::mojom::PubkySessionHost> receiver,
      pubky_session::PubkySessionService* service,
      HostContentSettingsMap* settings);
  ~PubkySessionHostImpl() override;

  bool IsEligible();
  content::WebContents* web_contents();

  void AdvanceRequest();
  void FailRequest(blink::mojom::PubkyStatus status);
  void OnRequestDone();
  void ContinueRequest(std::vector<pubky_session::Capability> scopes,
                       RequestSessionCallback callback);
  void OnAccessDecision(std::vector<pubky_session::Capability> scopes,
                        RequestSessionCallback callback,
                        bool allowed);
  void OnScopesApproved(std::vector<pubky_session::Capability> scopes,
                        RequestSessionCallback callback,
                        pubky_session::PubkySessionService::SignInResult result);
  void Grant(const std::vector<pubky_session::Capability>& scopes,
             RequestSessionCallback callback);

  // Whether this document may make a storage call for `path`.
  blink::mojom::PubkyStatus CheckAccess(const std::string& path,
                                        bool write,
                                        bool directory);

  // Null for profiles without Pubky sessions, such as Guest.
  const raw_ptr<pubky_session::PubkySessionService> service_;
  const raw_ptr<HostContentSettingsMap> settings_;
  // One requestSession() at a time, from the call until it answers.
  bool request_in_progress_ = false;
  std::unique_ptr<PendingRequest> pending_;
  base::OneShotTimer sign_in_timer_;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      observation_{this};
  base::WeakPtrFactory<PubkySessionHostImpl> weak_factory_{this};
};

#endif  // CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_HOST_IMPL_H_

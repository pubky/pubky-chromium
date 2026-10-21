// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_SITE_PROMPT_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_SITE_PROMPT_VIEW_H_

#include <string>
#include <vector>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/scoped_observation.h"
#include "chrome/browser/ui/views/location_bar/location_bar_bubble_delegate_view.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/base/interaction/element_identifier.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/views/bubble/bubble_dialog_delegate_view.h"
#include "url/origin.h"

namespace content {
class WebContents;
}  // namespace content

// The prompt a site's navigator.pubky.requestSession() opens, anchored to the
// address bar like a permission prompt. It names the site, the identity and
// the scopes the site does not have yet. Leaving the page, switching tabs or
// a fullscreen change closes it.
//
// Two kinds: for scopes within the browser's approval it asks Allow or Don't
// allow. For scopes beyond it, such as /priv/ paths, it shows the pending
// Pubky Ring approval as a QR code: approving in Ring is the answer, and
// Cancel cancels the approval.
class PubkySitePromptView
    : public LocationBarBubbleDelegateView,
      public pubky_session::PubkySessionService::Observer {
  METADATA_HEADER(PubkySitePromptView, LocationBarBubbleDelegateView)

 public:
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kQrCodeElementId);

  // `callback` runs once: true for Allow, false for Don't allow, for closing
  // the prompt, or when it cannot be shown.
  static void ShowAccessPrompt(
      content::WebContents* contents,
      const url::Origin& origin,
      const std::vector<pubky_session::Capability>& scopes,
      base::OnceCallback<void(bool allowed)> callback);
  static void ShowRingPrompt(
      content::WebContents* contents,
      const url::Origin& origin,
      const std::vector<pubky_session::Capability>& scopes);

  // The open prompt shown last, if any.
  static PubkySitePromptView* GetForTesting();

  // Use ShowAccessPrompt() or ShowRingPrompt().
  PubkySitePromptView(views::BubbleAnchor anchor,
                      views::BubbleBorder::Arrow arrow,
                      content::WebContents* contents,
                      pubky_session::PubkySessionService* service,
                      const url::Origin& origin,
                      const std::vector<pubky_session::Capability>& scopes,
                      bool ring,
                      base::OnceCallback<void(bool allowed)> callback);
  PubkySitePromptView(const PubkySitePromptView&) = delete;
  PubkySitePromptView& operator=(const PubkySitePromptView&) = delete;
  ~PubkySitePromptView() override;

  bool is_ring_prompt_for_testing() const { return ring_; }

  // content::WebContentsObserver:
  void PrimaryPageChanged(content::Page& page) override;

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

 private:
  static void Show(content::WebContents* contents,
                   const url::Origin& origin,
                   const std::vector<pubky_session::Capability>& scopes,
                   bool ring,
                   base::OnceCallback<void(bool allowed)> callback);

  void AddContents(const url::Origin& origin,
                   const std::vector<pubky_session::Capability>& scopes,
                   bool connected);
  void AddRingApproval();
  // Answers the access prompt, or cancels the Ring approval if it is still
  // the one this prompt shows.
  void Finish(bool allowed);

  const bool ring_;
  const raw_ptr<pubky_session::PubkySessionService> service_;
  // The Ring approval this prompt shows.
  const std::string ring_link_;
  base::OnceCallback<void(bool allowed)> callback_;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      observation_{this};
};

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_SITE_PROMPT_VIEW_H_

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUTTON_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUTTON_H_

#include <string>

#include "base/memory/raw_ptr.h"
#include "base/scoped_observation.h"
#include "chrome/browser/ui/views/toolbar/toolbar_button.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/base/metadata/metadata_header_macros.h"

class Browser;

// The toolbar's identity button. It replaces the profile avatar button: it
// shows the profile's Pubky identity and its sign-in state, and opens
// PubkyIdentityBubbleView. Each browser profile holds one identity.
class PubkyIdentityButton
    : public ToolbarButton,
      public pubky_session::PubkySessionService::Observer {
  METADATA_HEADER(PubkyIdentityButton, ToolbarButton)

 public:
  explicit PubkyIdentityButton(Browser* browser);
  PubkyIdentityButton(const PubkyIdentityButton&) = delete;
  PubkyIdentityButton& operator=(const PubkyIdentityButton&) = delete;
  ~PubkyIdentityButton() override;

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

  // Opens the identity panel, starting sign-in when signed out outside
  // Incognito. Also used when a site asks for the identity.
  void OpenPanel();

  std::u16string label_for_testing() const { return label_; }

 private:
  void ButtonPressed();
  void UpdateAppearance();

  const raw_ptr<Browser> browser_;
  // Null for profiles without Pubky sessions, such as Guest.
  const raw_ptr<pubky_session::PubkySessionService> service_;
  std::u16string label_;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      observation_{this};
};

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_BUTTON_H_

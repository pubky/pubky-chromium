// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UI_H_
#define CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UI_H_

#include <vector>

#include "base/no_destructor.h"
#include "chrome/browser/pubky_session/pubky_session_host_impl.h"

// The browser UI behind navigator.pubky: a site calling it while signed out
// opens the toolbar's identity panel. There is no site prompt yet, so
// requests for scopes a site does not have are declined.
class PubkyIdentityUi : public PubkySessionHostImpl::Ui {
 public:
  static PubkyIdentityUi* GetInstance();

  PubkyIdentityUi(const PubkyIdentityUi&) = delete;
  PubkyIdentityUi& operator=(const PubkyIdentityUi&) = delete;

  // PubkySessionHostImpl::Ui:
  void OpenSignIn(content::WebContents* contents) override;
  void RequestAccess(content::WebContents* contents,
                     const url::Origin& origin,
                     const std::vector<pubky_session::Capability>& scopes,
                     base::OnceCallback<void(bool allowed)> callback) override;

 private:
  friend base::NoDestructor<PubkyIdentityUi>;

  PubkyIdentityUi();
  ~PubkyIdentityUi() override;
};

#endif  // CHROME_BROWSER_UI_VIEWS_TOOLBAR_PUBKY_IDENTITY_UI_H_

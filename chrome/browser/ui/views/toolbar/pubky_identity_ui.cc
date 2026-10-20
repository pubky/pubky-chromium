// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/toolbar/pubky_identity_ui.h"

#include <utility>

#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views/toolbar/pubky_identity_button.h"
#include "chrome/browser/ui/views/toolbar/toolbar_view.h"
#include "components/tabs/public/tab_interface.h"

// static
PubkyIdentityUi* PubkyIdentityUi::GetInstance() {
  static base::NoDestructor<PubkyIdentityUi> instance;
  return instance.get();
}

PubkyIdentityUi::PubkyIdentityUi() = default;
PubkyIdentityUi::~PubkyIdentityUi() = default;

void PubkyIdentityUi::OpenSignIn(content::WebContents* contents) {
  tabs::TabInterface* tab = tabs::TabInterface::MaybeGetFromContents(contents);
  BrowserView* browser_view =
      tab ? BrowserView::GetBrowserViewForBrowser(
                tab->GetBrowserWindowInterface())
          : nullptr;
  PubkyIdentityButton* button =
      browser_view && browser_view->toolbar()
          ? browser_view->toolbar()->pubky_identity_button()
          : nullptr;
  if (button && button->GetVisible()) {
    button->OpenPanel();
  }
}

void PubkyIdentityUi::RequestAccess(
    content::WebContents* contents,
    const url::Origin& origin,
    const std::vector<pubky_session::Capability>& scopes,
    base::OnceCallback<void(bool allowed)> callback) {
  std::move(callback).Run(false);
}

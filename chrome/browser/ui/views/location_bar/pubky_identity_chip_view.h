// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_LOCATION_BAR_PUBKY_IDENTITY_CHIP_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_LOCATION_BAR_PUBKY_IDENTITY_CHIP_VIEW_H_

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/scoped_observation.h"
#include "components/content_settings/core/browser/content_settings_observer.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/pubky_session/pubky_session_service.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/views/controls/button/label_button.h"

namespace content {
class WebContents;
}  // namespace content

// The address bar chip that shows which Pubky identity the current site uses,
// while the site has access. Pressing it opens page info, where the site can
// be disconnected.
class PubkyIdentityChipView
    : public views::LabelButton,
      public pubky_session::PubkySessionService::Observer,
      public content_settings::Observer {
  METADATA_HEADER(PubkyIdentityChipView, views::LabelButton)

 public:
  explicit PubkyIdentityChipView(base::RepeatingClosure open_page_info);
  PubkyIdentityChipView(const PubkyIdentityChipView&) = delete;
  PubkyIdentityChipView& operator=(const PubkyIdentityChipView&) = delete;
  ~PubkyIdentityChipView() override;

  // Follows the tab the address bar shows.
  void Update(content::WebContents* contents);

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

  // content_settings::Observer:
  void OnContentSettingChanged(
      const ContentSettingsPattern& primary_pattern,
      const ContentSettingsPattern& secondary_pattern,
      ContentSettingsTypeSet content_type_set) override;

 private:
  void Refresh();

  base::WeakPtr<content::WebContents> contents_;
  raw_ptr<pubky_session::PubkySessionService> service_ = nullptr;
  raw_ptr<HostContentSettingsMap> settings_ = nullptr;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      service_observation_{this};
  base::ScopedObservation<HostContentSettingsMap, content_settings::Observer>
      settings_observation_{this};
};

#endif  // CHROME_BROWSER_UI_VIEWS_LOCATION_BAR_PUBKY_IDENTITY_CHIP_VIEW_H_

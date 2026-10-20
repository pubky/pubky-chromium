// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_SETTINGS_PUBKY_IDENTITY_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_SETTINGS_PUBKY_IDENTITY_HANDLER_H_

#include "base/memory/raw_ptr.h"
#include "base/scoped_observation.h"
#include "base/values.h"
#include "chrome/browser/ui/webui/settings/settings_page_ui_handler.h"
#include "components/content_settings/core/browser/content_settings_observer.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/pubky_session/pubky_session_service.h"

class Profile;

namespace settings {

// Serves chrome://settings/pubky: the profile's Pubky identity and approval,
// every site using it with its access, and sign-out. Sends
// "pubky-identity-changed" whenever any of it changes.
class PubkyIdentityHandler
    : public SettingsPageUIHandler,
      public pubky_session::PubkySessionService::Observer,
      public content_settings::Observer {
 public:
  explicit PubkyIdentityHandler(Profile* profile);
  PubkyIdentityHandler(const PubkyIdentityHandler&) = delete;
  PubkyIdentityHandler& operator=(const PubkyIdentityHandler&) = delete;
  ~PubkyIdentityHandler() override;

  // SettingsPageUIHandler:
  void RegisterMessages() override;
  void OnJavascriptAllowed() override;
  void OnJavascriptDisallowed() override;

  // pubky_session::PubkySessionService::Observer:
  void OnPubkySessionChanged() override;

  // content_settings::Observer:
  void OnContentSettingChanged(
      const ContentSettingsPattern& primary_pattern,
      const ContentSettingsPattern& secondary_pattern,
      ContentSettingsTypeSet content_type_set) override;

  base::DictValue GetIdentityForTesting() { return GetIdentity(); }

 private:
  void HandleGetPubkyIdentity(const base::ListValue& args);
  // Args: the site's origin, as GetIdentity() listed it.
  void HandleRemovePubkySite(const base::ListValue& args);
  void HandleSignOutPubky(const base::ListValue& args);

  base::DictValue GetIdentity();

  // Null for profiles without Pubky sessions, such as Guest.
  const raw_ptr<pubky_session::PubkySessionService> service_;
  const raw_ptr<HostContentSettingsMap> settings_;
  base::ScopedObservation<pubky_session::PubkySessionService,
                          pubky_session::PubkySessionService::Observer>
      service_observation_{this};
  base::ScopedObservation<HostContentSettingsMap, content_settings::Observer>
      settings_observation_{this};
};

}  // namespace settings

#endif  // CHROME_BROWSER_UI_WEBUI_SETTINGS_PUBKY_IDENTITY_HANDLER_H_

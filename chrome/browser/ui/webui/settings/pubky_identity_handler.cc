// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/settings/pubky_identity_handler.h"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/i18n/time_formatting.h"
#include "base/strings/utf_string_conversions.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/pubky_session/pubky_identity_text.h"
#include "chrome/browser/pubky_session/pubky_session_service_factory.h"
#include "chrome/browser/pubky_session/pubky_site_access.h"
#include "chrome/grit/generated_resources.h"
#include "components/pubky_session/core/crypto.h"
#include "components/url_formatter/elide_url.h"
#include "ui/base/l10n/l10n_util.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace settings {

namespace {

using State = pubky_session::PubkySessionService::State;

}  // namespace

PubkyIdentityHandler::PubkyIdentityHandler(Profile* profile)
    : service_(PubkySessionServiceFactory::GetForProfile(profile)),
      settings_(HostContentSettingsMapFactory::GetForProfile(profile)) {}

PubkyIdentityHandler::~PubkyIdentityHandler() = default;

void PubkyIdentityHandler::RegisterMessages() {
  web_ui()->RegisterMessageCallback(
      "getPubkyIdentity",
      base::BindRepeating(&PubkyIdentityHandler::HandleGetPubkyIdentity,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "removePubkySite",
      base::BindRepeating(&PubkyIdentityHandler::HandleRemovePubkySite,
                          base::Unretained(this)));
  web_ui()->RegisterMessageCallback(
      "signOutPubky",
      base::BindRepeating(&PubkyIdentityHandler::HandleSignOutPubky,
                          base::Unretained(this)));
}

void PubkyIdentityHandler::OnJavascriptAllowed() {
  if (service_) {
    service_observation_.Observe(service_.get());
  }
  settings_observation_.Observe(settings_.get());
}

void PubkyIdentityHandler::OnJavascriptDisallowed() {
  service_observation_.Reset();
  settings_observation_.Reset();
}

void PubkyIdentityHandler::OnPubkySessionChanged() {
  FireWebUIListener("pubky-identity-changed", GetIdentity());
}

void PubkyIdentityHandler::OnContentSettingChanged(
    const ContentSettingsPattern& primary_pattern,
    const ContentSettingsPattern& secondary_pattern,
    ContentSettingsTypeSet content_type_set) {
  if (content_type_set.Contains(ContentSettingsType::PUBKY_SITE_ACCESS)) {
    FireWebUIListener("pubky-identity-changed", GetIdentity());
  }
}

void PubkyIdentityHandler::HandleGetPubkyIdentity(
    const base::ListValue& args) {
  AllowJavascript();
  ResolveJavascriptCallback(args[0], GetIdentity());
}

void PubkyIdentityHandler::HandleRemovePubkySite(
    const base::ListValue& args) {
  const std::string* origin = args.empty() ? nullptr : args[0].GetIfString();
  if (!origin) {
    return;
  }
  const url::Origin site = url::Origin::Create(GURL(*origin));
  if (!site.opaque()) {
    pubky_session::RemoveSiteAccess(settings_, site);
  }
}

void PubkyIdentityHandler::HandleSignOutPubky(const base::ListValue& args) {
  if (service_) {
    service_->SignOut();
  }
}

base::DictValue PubkyIdentityHandler::GetIdentity() {
  base::DictValue identity;
  identity.Set("available", !!service_);
  std::optional<pubky_session::Key> user =
      service_ ? service_->user() : std::nullopt;
  identity.Set("signedIn", user.has_value());
  if (!user) {
    return identity;
  }
  const std::u16string label = PubkyIdentityLabel(*service_);
  identity.Set("name", label);
  identity.Set("publicKey", pubky_session::EncodeZ32(*user));
  const std::u16string scopes = DescribeScopes(service_->capabilities());
  const std::u16string homeserver =
      service_->homeserver() ? ShortPubkyKey(*service_->homeserver())
                             : std::u16string();
  const bool expired = service_->state() == State::kApprovalExpired;
  identity.Set("expired", expired);
  identity.Set("approval",
               l10n_util::GetStringFUTF16(
                   expired ? IDS_PUBKY_SETTINGS_APPROVAL_EXPIRED
                           : IDS_PUBKY_SETTINGS_APPROVAL,
                   scopes, homeserver));

  std::vector<std::pair<url::Origin, pubky_session::SiteAccess>> sites =
      pubky_session::GetAllSiteAccess(settings_, *user);
  std::ranges::sort(sites, [](const auto& a, const auto& b) {
    return a.second.since < b.second.since;
  });
  base::ListValue list;
  for (const auto& [origin, access] : sites) {
    list.Append(
        base::DictValue()
            .Set("origin", origin.Serialize())
            .Set("site",
                 url_formatter::FormatOriginForSecurityDisplay(
                     origin, url_formatter::SchemeDisplay::OMIT_HTTP_AND_HTTPS))
            .Set("access", DescribeScopes(access.scopes))
            .Set("since", access.since.is_null()
                              ? std::u16string()
                              : base::TimeFormatShortDate(access.since)));
  }
  identity.Set("sites", std::move(list));
  return identity;
}

}  // namespace settings

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/pubky_session/pubky_site_access.h"

#include <optional>
#include <string>
#include <utility>

#include "base/json/values_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/content_settings/core/common/content_settings.h"
#include "components/content_settings/core/common/content_settings_types.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace pubky_session {

namespace {

constexpr char kUserKey[] = "user";
constexpr char kScopesKey[] = "scopes";
constexpr char kSinceKey[] = "since";

base::Value GetRecord(HostContentSettingsMap* map, const url::Origin& origin) {
  return map->GetWebsiteSetting(origin.GetURL(), GURL(),
                                ContentSettingsType::PUBKY_SITE_ACCESS);
}

// The record's scopes if it belongs to `user`.
std::optional<std::vector<Capability>> ScopesFor(const base::Value& record,
                                                 const Key& user) {
  const base::DictValue* dict = record.GetIfDict();
  const std::string* record_user = dict ? dict->FindString(kUserKey) : nullptr;
  const std::string* scopes = dict ? dict->FindString(kScopesKey) : nullptr;
  if (!record_user || *record_user != EncodeZ32(user) || !scopes) {
    return std::nullopt;
  }
  return ParseCapabilities(*scopes);
}

}  // namespace

SiteAccess::SiteAccess() = default;
SiteAccess::SiteAccess(const SiteAccess&) = default;
SiteAccess& SiteAccess::operator=(const SiteAccess&) = default;
SiteAccess::~SiteAccess() = default;

std::optional<SiteAccess> GetSiteAccess(HostContentSettingsMap* map,
                                        const url::Origin& origin,
                                        const Key& user) {
  const base::Value record = GetRecord(map, origin);
  std::optional<std::vector<Capability>> scopes = ScopesFor(record, user);
  if (!scopes || scopes->empty()) {
    return std::nullopt;
  }
  SiteAccess access;
  access.scopes = std::move(*scopes);
  access.since = base::ValueToTime(record.GetDict().Find(kSinceKey))
                     .value_or(base::Time());
  return access;
}

std::vector<std::pair<url::Origin, SiteAccess>> GetAllSiteAccess(
    HostContentSettingsMap* map,
    const Key& user) {
  std::vector<std::pair<url::Origin, SiteAccess>> sites;
  for (const ContentSettingPatternSource& entry :
       map->GetSettingsForOneType(ContentSettingsType::PUBKY_SITE_ACCESS)) {
    const url::Origin origin =
        url::Origin::Create(GURL(entry.primary_pattern.ToString()));
    if (origin.opaque()) {
      continue;
    }
    if (std::optional<SiteAccess> access = GetSiteAccess(map, origin, user)) {
      sites.emplace_back(origin, std::move(*access));
    }
  }
  return sites;
}

std::vector<Capability> GetSiteScopes(HostContentSettingsMap* map,
                                      const url::Origin& origin,
                                      const Key& user) {
  return ScopesFor(GetRecord(map, origin), user)
      .value_or(std::vector<Capability>());
}

void AllowSiteScopes(HostContentSettingsMap* map,
                     const url::Origin& origin,
                     const Key& user,
                     const std::vector<Capability>& scopes) {
  const base::Value record = GetRecord(map, origin);
  std::optional<std::vector<Capability>> current = ScopesFor(record, user);
  base::Value since = base::TimeToValue(base::Time::Now());
  if (current) {
    if (const base::Value* first = record.GetDict().Find(kSinceKey)) {
      since = first->Clone();
    }
  }
  std::vector<Capability> all = current.value_or(std::vector<Capability>());
  all.insert(all.end(), scopes.begin(), scopes.end());
  // Parsing the joined list merges entries with the same scope.
  std::optional<std::vector<Capability>> merged =
      ParseCapabilities(CapabilitiesToString(all));
  map->SetWebsiteSettingDefaultScope(
      origin.GetURL(), GURL(), ContentSettingsType::PUBKY_SITE_ACCESS,
      base::Value(base::DictValue()
                      .Set(kUserKey, EncodeZ32(user))
                      .Set(kScopesKey, CapabilitiesToString(*merged))
                      .Set(kSinceKey, std::move(since))));
}

void RemoveSiteAccess(HostContentSettingsMap* map, const url::Origin& origin) {
  map->SetWebsiteSettingDefaultScope(origin.GetURL(), GURL(),
                                     ContentSettingsType::PUBKY_SITE_ACCESS,
                                     base::Value());
}

}  // namespace pubky_session

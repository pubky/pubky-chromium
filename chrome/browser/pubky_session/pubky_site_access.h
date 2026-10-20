// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PUBKY_SESSION_PUBKY_SITE_ACCESS_H_
#define CHROME_BROWSER_PUBKY_SESSION_PUBKY_SITE_ACCESS_H_

#include <optional>
#include <utility>
#include <vector>

#include "base/time/time.h"
#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"
#include "url/origin.h"

class HostContentSettingsMap;

// Each site's access to the user's Pubky storage, kept in the
// PUBKY_SITE_ACCESS website setting. A record belongs to the identity that
// allowed it: after signing in with another key, the site starts over.
namespace pubky_session {

struct SiteAccess {
  SiteAccess();
  SiteAccess(const SiteAccess&);
  SiteAccess& operator=(const SiteAccess&);
  ~SiteAccess();

  std::vector<Capability> scopes;
  // When the site was first allowed.
  base::Time since;
};

// What `origin` may use with `user`'s identity, if anything.
std::optional<SiteAccess> GetSiteAccess(HostContentSettingsMap* map,
                                        const url::Origin& origin,
                                        const Key& user);

// Every site with access for `user`'s identity, in no particular order.
std::vector<std::pair<url::Origin, SiteAccess>> GetAllSiteAccess(
    HostContentSettingsMap* map,
    const Key& user);

// The scopes `origin` may use with `user`'s identity. Empty when none.
std::vector<Capability> GetSiteScopes(HostContentSettingsMap* map,
                                      const url::Origin& origin,
                                      const Key& user);

// Adds `scopes` to what `origin` may use with `user`'s identity, keeping the
// date of the first grant.
void AllowSiteScopes(HostContentSettingsMap* map,
                     const url::Origin& origin,
                     const Key& user,
                     const std::vector<Capability>& scopes);

// Removes all of `origin`'s access. Its next call fails.
void RemoveSiteAccess(HostContentSettingsMap* map, const url::Origin& origin);

}  // namespace pubky_session

#endif  // CHROME_BROWSER_PUBKY_SESSION_PUBKY_SITE_ACCESS_H_

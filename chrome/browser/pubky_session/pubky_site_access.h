// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PUBKY_SESSION_PUBKY_SITE_ACCESS_H_
#define CHROME_BROWSER_PUBKY_SESSION_PUBKY_SITE_ACCESS_H_

#include <vector>

#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"

class HostContentSettingsMap;

namespace url {
class Origin;
}  // namespace url

// Each site's access to the user's Pubky storage, kept in the
// PUBKY_SITE_ACCESS website setting. A record belongs to the identity that
// allowed it: after signing in with another key, the site starts over.
namespace pubky_session {

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

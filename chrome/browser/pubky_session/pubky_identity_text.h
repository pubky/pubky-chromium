// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PUBKY_SESSION_PUBKY_IDENTITY_TEXT_H_
#define CHROME_BROWSER_PUBKY_SESSION_PUBKY_IDENTITY_TEXT_H_

#include <string>
#include <vector>

#include "components/pubky_session/core/capabilities.h"
#include "components/pubky_session/core/crypto.h"

namespace pubky_session {
class PubkySessionService;
}  // namespace pubky_session

// How the browser UI names the Pubky identity and describes site access.

// "8um7…1dty": the first and last four characters of a key's z-base-32 form.
std::u16string ShortPubkyKey(const pubky_session::Key& key);

// The name from the user's profile, or the short key.
std::u16string PubkyIdentityLabel(
    const pubky_session::PubkySessionService& service);

// Whether `scope` is outside public storage, /pub/.
bool IsPrivateScope(const pubky_session::Capability& scope);

// "Read and write /pub/example.com/", or "Private storage · read
// /priv/notes/" for scopes outside /pub/.
std::u16string DescribeScope(const pubky_session::Capability& scope);

// Every scope described, separated by commas.
std::u16string DescribeScopes(
    const std::vector<pubky_session::Capability>& scopes);

#endif  // CHROME_BROWSER_PUBKY_SESSION_PUBKY_IDENTITY_TEXT_H_

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PUBKY_SESSION_CORE_CAPABILITIES_H_
#define COMPONENTS_PUBKY_SESSION_CORE_CAPABILITIES_H_

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Pubky capabilities ("<scope>:<actions>", for example "/pub/app/:rw") and
// homeserver storage paths, following pubky-common's rules.
namespace pubky_session {

struct Capability {
  // A canonical storage path. A scope ending in '/' is a directory and covers
  // every path below it; any other scope covers only itself.
  std::string scope;
  bool read = false;
  bool write = false;
  // The "e" action: scoped encryption keys.
  bool encryption_keys = false;

  bool operator==(const Capability&) const = default;
};

// Whether `path` is a canonical decoded storage path: absolute, no empty,
// "." or ".." segments, no control characters or backslashes, segments of at
// most 255 bytes, at most 972 bytes in total and no trailing whitespace.
bool IsCanonicalStoragePath(std::string_view path);

// Parses one capability. Actions are any of 'r', 'w' and 'e'; repeats are
// merged. The scope must be canonical and contain no ':' or ','.
std::optional<Capability> ParseCapability(std::string_view text);

// Parses a comma-separated list. An empty string is an empty list. Entries
// with the same scope are merged.
std::optional<std::vector<Capability>> ParseCapabilities(std::string_view text);

// Canonical text, with actions in the order r, w, e.
std::string CapabilityToString(const Capability& capability);
std::string CapabilitiesToString(const std::vector<Capability>& capabilities);

// The SDK's rule: equal, or `scope` is a directory and `path` starts with it.
bool ScopeCoversPath(std::string_view scope, std::string_view path);

// Whether every action of `requested` is allowed by some capability in
// `granted` whose scope covers `requested.scope`.
bool CapabilitiesCover(const std::vector<Capability>& granted,
                       const Capability& requested);

}  // namespace pubky_session

#endif  // COMPONENTS_PUBKY_SESSION_CORE_CAPABILITIES_H_

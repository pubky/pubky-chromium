// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/capabilities.h"

#include <stdint.h>

namespace pubky_session {

namespace {

constexpr size_t kMaxSegmentLength = 255;
constexpr size_t kMaxPathLength = 972;

// Control characters in UTF-8: C0 controls, DEL and the C1 range, which is
// encoded as 0xC2 0x80..0x9F.
bool HasControlCharacter(std::string_view text) {
  for (size_t i = 0; i < text.size(); ++i) {
    const uint8_t byte = static_cast<uint8_t>(text[i]);
    if (byte < 0x20 || byte == 0x7F) {
      return true;
    }
    if (byte == 0xC2 && i + 1 < text.size()) {
      const uint8_t next = static_cast<uint8_t>(text[i + 1]);
      if (next >= 0x80 && next <= 0x9F) {
        return true;
      }
    }
  }
  return false;
}

// Trailing ASCII whitespace or U+00A0, U+0085 and U+3000, the non-ASCII
// whitespace a path is most likely to end with.
bool EndsWithWhitespace(std::string_view text) {
  if (text.empty()) {
    return false;
  }
  const char last = text.back();
  if (last == ' ' || last == '\t' || last == '\n' || last == '\r' ||
      last == '\v' || last == '\f') {
    return true;
  }
  return text.ends_with("\xC2\xA0") || text.ends_with("\xC2\x85") ||
         text.ends_with("\xE3\x80\x80");
}

void MergeInto(std::vector<Capability>& list, const Capability& capability) {
  for (Capability& existing : list) {
    if (existing.scope == capability.scope) {
      existing.read |= capability.read;
      existing.write |= capability.write;
      existing.encryption_keys |= capability.encryption_keys;
      return;
    }
  }
  list.push_back(capability);
}

}  // namespace

bool IsCanonicalStoragePath(std::string_view path) {
  if (path.empty() || path.front() != '/' || path.size() > kMaxPathLength) {
    return false;
  }
  if (path == "/") {
    return true;
  }
  std::string_view rest = path.substr(1);
  while (true) {
    const size_t slash = rest.find('/');
    const std::string_view segment = rest.substr(0, slash);
    const bool last = slash == std::string_view::npos;
    if (segment.empty()) {
      // Only a trailing slash may leave an empty final segment.
      if (last) {
        break;
      }
      return false;
    }
    if (segment == "." || segment == ".." ||
        segment.size() > kMaxSegmentLength || HasControlCharacter(segment) ||
        segment.find('\\') != std::string_view::npos) {
      return false;
    }
    if (last) {
      break;
    }
    rest = rest.substr(slash + 1);
  }
  return !EndsWithWhitespace(path);
}

std::optional<Capability> ParseCapability(std::string_view text) {
  const size_t colon = text.find(':');
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view scope = text.substr(0, colon);
  const std::string_view actions = text.substr(colon + 1);
  if (actions.empty() || actions.find(':') != std::string_view::npos ||
      scope.find(',') != std::string_view::npos ||
      !IsCanonicalStoragePath(scope)) {
    return std::nullopt;
  }
  Capability capability;
  capability.scope = std::string(scope);
  for (char action : actions) {
    switch (action) {
      case 'r':
        capability.read = true;
        break;
      case 'w':
        capability.write = true;
        break;
      case 'e':
        capability.encryption_keys = true;
        break;
      default:
        return std::nullopt;
    }
  }
  return capability;
}

std::optional<std::vector<Capability>> ParseCapabilities(
    std::string_view text) {
  std::vector<Capability> list;
  if (text.empty()) {
    return list;
  }
  while (true) {
    const size_t comma = text.find(',');
    std::optional<Capability> capability =
        ParseCapability(text.substr(0, comma));
    if (!capability) {
      return std::nullopt;
    }
    MergeInto(list, *capability);
    if (comma == std::string_view::npos) {
      return list;
    }
    text = text.substr(comma + 1);
  }
}

std::string CapabilityToString(const Capability& capability) {
  std::string out = capability.scope;
  out.push_back(':');
  if (capability.read) {
    out.push_back('r');
  }
  if (capability.write) {
    out.push_back('w');
  }
  if (capability.encryption_keys) {
    out.push_back('e');
  }
  return out;
}

std::string CapabilitiesToString(const std::vector<Capability>& capabilities) {
  std::string out;
  for (const Capability& capability : capabilities) {
    if (!out.empty()) {
      out.push_back(',');
    }
    out.append(CapabilityToString(capability));
  }
  return out;
}

bool ScopeCoversPath(std::string_view scope, std::string_view path) {
  return scope == path || (scope.ends_with('/') && path.starts_with(scope));
}

bool CapabilitiesCover(const std::vector<Capability>& granted,
                       const Capability& requested) {
  const auto allows = [&](bool Capability::*action) {
    for (const Capability& capability : granted) {
      if (capability.*action &&
          ScopeCoversPath(capability.scope, requested.scope)) {
        return true;
      }
    }
    return false;
  };
  return (!requested.read || allows(&Capability::read)) &&
         (!requested.write || allows(&Capability::write)) &&
         (!requested.encryption_keys || allows(&Capability::encryption_keys));
}

}  // namespace pubky_session

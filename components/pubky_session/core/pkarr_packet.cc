// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/pkarr_packet.h"

namespace pubky_session {

namespace {

constexpr size_t kTimestampSize = 8;
constexpr size_t kHeaderSize = 12;
constexpr uint16_t kTypeSvcb = 64;
constexpr uint16_t kTypeHttps = 65;
constexpr int kMaxPointerJumps = 64;
constexpr size_t kMaxNameLength = 255;

uint8_t ByteAt(std::string_view data, size_t offset) {
  return static_cast<uint8_t>(data[offset]);
}

bool ReadU16(std::string_view data, size_t& offset, uint16_t& out) {
  if (offset + 2 > data.size()) {
    return false;
  }
  out = static_cast<uint16_t>((ByteAt(data, offset) << 8) |
                              ByteAt(data, offset + 1));
  offset += 2;
  return true;
}

// Reads a possibly compressed DNS name starting at `offset` in `packet`,
// advancing `offset` past it.
std::optional<std::string> ReadName(std::string_view packet, size_t& offset) {
  std::string name;
  size_t position = offset;
  bool jumped = false;
  int jumps = 0;
  while (true) {
    if (position >= packet.size()) {
      return std::nullopt;
    }
    const uint8_t length = ByteAt(packet, position);
    if ((length & 0xC0) == 0xC0) {
      if (position + 1 >= packet.size() || ++jumps > kMaxPointerJumps) {
        return std::nullopt;
      }
      const size_t target =
          (static_cast<size_t>(length & 0x3F) << 8) |
          ByteAt(packet, position + 1);
      if (!jumped) {
        offset = position + 2;
        jumped = true;
      }
      position = target;
      continue;
    }
    if ((length & 0xC0) != 0) {
      return std::nullopt;
    }
    if (length == 0) {
      if (!jumped) {
        offset = position + 1;
      }
      return name;
    }
    if (position + 1 + length > packet.size()) {
      return std::nullopt;
    }
    if (!name.empty()) {
      name.push_back('.');
    }
    name.append(packet.substr(position + 1, length));
    if (name.size() > kMaxNameLength) {
      return std::nullopt;
    }
    position += 1 + length;
  }
}

bool EqualsIgnoreAsciiCase(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') {
      x = static_cast<char>(x - 'A' + 'a');
    }
    if (y >= 'A' && y <= 'Z') {
      y = static_cast<char>(y - 'A' + 'a');
    }
    if (x != y) {
      return false;
    }
  }
  return true;
}

std::string Signable(uint64_t timestamp, std::string_view dns_packet) {
  std::string signable = "3:seqi" + std::to_string(timestamp) + "e1:v" +
                         std::to_string(dns_packet.size()) + ":";
  signable.append(dns_packet);
  return signable;
}

void AppendU16(std::string& out, uint16_t value) {
  out.push_back(static_cast<char>(value >> 8));
  out.push_back(static_cast<char>(value & 0xFF));
}

void AppendName(std::string& out, std::string_view name) {
  while (!name.empty()) {
    const size_t dot = name.find('.');
    const std::string_view label = name.substr(0, dot);
    out.push_back(static_cast<char>(label.size()));
    out.append(label);
    name = dot == std::string_view::npos ? std::string_view()
                                          : name.substr(dot + 1);
  }
  out.push_back('\0');
}

}  // namespace

std::optional<SignedPacket> VerifyRelayPayload(const Key& public_key,
                                               std::string_view payload) {
  if (payload.size() < kSignatureSize + kTimestampSize ||
      payload.size() > kMaxRelayPayloadSize) {
    return std::nullopt;
  }
  const std::string_view signature = payload.substr(0, kSignatureSize);
  uint64_t timestamp = 0;
  for (size_t i = 0; i < kTimestampSize; ++i) {
    timestamp = (timestamp << 8) | ByteAt(payload, kSignatureSize + i);
  }
  const std::string_view dns_packet =
      payload.substr(kSignatureSize + kTimestampSize);
  if (!Ed25519Verify(public_key, Signable(timestamp, dns_packet), signature)) {
    return std::nullopt;
  }
  return SignedPacket{timestamp, std::string(dns_packet)};
}

std::optional<Key> FindHomeserver(const Key& user,
                                  std::string_view dns_packet) {
  if (dns_packet.size() < kHeaderSize) {
    return std::nullopt;
  }
  size_t offset = 4;
  uint16_t questions = 0;
  uint16_t answers = 0;
  if (!ReadU16(dns_packet, offset, questions) ||
      !ReadU16(dns_packet, offset, answers)) {
    return std::nullopt;
  }
  offset = kHeaderSize;
  for (uint16_t i = 0; i < questions; ++i) {
    if (!ReadName(dns_packet, offset) || offset + 4 > dns_packet.size()) {
      return std::nullopt;
    }
    offset += 4;
  }

  const std::string owner = "_pubky." + EncodeZ32(user);
  for (uint16_t i = 0; i < answers; ++i) {
    std::optional<std::string> name = ReadName(dns_packet, offset);
    uint16_t type = 0;
    uint16_t record_class = 0;
    uint16_t ttl_high = 0;
    uint16_t ttl_low = 0;
    uint16_t rdata_length = 0;
    if (!name || !ReadU16(dns_packet, offset, type) ||
        !ReadU16(dns_packet, offset, record_class) ||
        !ReadU16(dns_packet, offset, ttl_high) ||
        !ReadU16(dns_packet, offset, ttl_low) ||
        !ReadU16(dns_packet, offset, rdata_length) ||
        offset + rdata_length > dns_packet.size()) {
      return std::nullopt;
    }
    const size_t rdata_end = offset + rdata_length;
    if ((type == kTypeSvcb || type == kTypeHttps) &&
        EqualsIgnoreAsciiCase(*name, owner)) {
      // SvcPriority, then TargetName. The first such record decides.
      size_t target_offset = offset;
      uint16_t priority = 0;
      if (!ReadU16(dns_packet, target_offset, priority) ||
          target_offset > rdata_end) {
        return std::nullopt;
      }
      std::optional<std::string> target = ReadName(dns_packet, target_offset);
      if (!target || target->find('.') != std::string::npos) {
        return std::nullopt;
      }
      return DecodeZ32(*target);
    }
    offset = rdata_end;
  }
  return std::nullopt;
}

std::string BuildPubkyRecordPacketForTesting(const Key& user,
                                             const Key& homeserver) {
  std::string packet;
  AppendU16(packet, 0);       // ID
  AppendU16(packet, 0x8400);  // Response, authoritative.
  AppendU16(packet, 0);       // Questions
  AppendU16(packet, 1);       // Answers
  AppendU16(packet, 0);       // Authority
  AppendU16(packet, 0);       // Additional
  AppendName(packet, "_pubky." + EncodeZ32(user));
  AppendU16(packet, kTypeHttps);
  AppendU16(packet, 1);  // IN
  AppendU16(packet, 0);
  AppendU16(packet, 3600);
  std::string rdata;
  AppendU16(rdata, 0);  // AliasMode
  AppendName(rdata, EncodeZ32(homeserver));
  AppendU16(packet, static_cast<uint16_t>(rdata.size()));
  packet.append(rdata);
  return packet;
}

std::string SignRelayPayloadForTesting(const Key& seed,
                                       uint64_t timestamp,
                                       std::string_view dns_packet) {
  const Signature signature =
      Ed25519Sign(seed, Signable(timestamp, dns_packet));
  std::string payload(signature.begin(), signature.end());
  for (int shift = 56; shift >= 0; shift -= 8) {
    payload.push_back(static_cast<char>((timestamp >> shift) & 0xFF));
  }
  payload.append(dns_packet);
  return payload;
}

}  // namespace pubky_session

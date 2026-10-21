// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pubky_session/core/capabilities.h"

#include "base/values.h"
#include "components/pubky_session/core/test_vectors.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace pubky_session {
namespace {

TEST(PubkySessionCapabilitiesTest, CoverageMatchesSdk) {
  const base::ListValue* cases = test::Vectors().FindList("covers");
  ASSERT_TRUE(cases);
  for (const base::Value& entry : *cases) {
    const base::DictValue& dict = entry.GetDict();
    const std::string& text = *dict.FindString("capability");
    const std::string& path = *dict.FindString("path");
    std::optional<Capability> capability = ParseCapability(text);
    ASSERT_TRUE(capability) << text;
    EXPECT_EQ(ScopeCoversPath(capability->scope, path),
              *dict.FindBool("covers"))
        << text << " " << path;
  }
}

TEST(PubkySessionCapabilitiesTest, CanonicalTextMatchesSdk) {
  const base::ListValue* cases = test::Vectors().FindList("canonical_caps");
  ASSERT_TRUE(cases);
  for (const base::Value& entry : *cases) {
    const base::DictValue& dict = entry.GetDict();
    std::optional<std::vector<Capability>> capabilities =
        ParseCapabilities(*dict.FindString("input"));
    ASSERT_TRUE(capabilities);
    EXPECT_EQ(CapabilitiesToString(*capabilities),
              *dict.FindString("canonical"));
  }
}

TEST(PubkySessionCapabilitiesTest, ParsesActions) {
  EXPECT_EQ(CapabilityToString(*ParseCapability("/pub/app/:ewrr")),
            "/pub/app/:rwe");
  EXPECT_EQ(*ParseCapabilities(""), std::vector<Capability>());
  EXPECT_EQ(CapabilitiesToString(*ParseCapabilities("/pub/a/:r,/pub/a/:w")),
            "/pub/a/:rw");
  EXPECT_FALSE(ParseCapability("/pub/app/:rx"));
  EXPECT_FALSE(ParseCapability("/pub/app/:"));
  EXPECT_FALSE(ParseCapability("/pub/app/"));
  EXPECT_FALSE(ParseCapability("/pub/a,b/:r"));
  EXPECT_FALSE(ParseCapability("/pub/../:r"));
  EXPECT_FALSE(ParseCapabilities("/pub/:r,"));
}

TEST(PubkySessionCapabilitiesTest, StoragePaths) {
  for (const char* path :
       {"/", "/pub/file.txt", "/priv/app/", "/pub/My File/\xC3\xBC" "ber",
        "/pub/a:b,c", "/a..", "/.hidden", "/..."}) {
    EXPECT_TRUE(IsCanonicalStoragePath(path)) << path;
  }
  for (const char* path : {"", "pub", "//", "/a//b", "/a/./b", "/a/../b",
                           "/a\\b", "/a\x01", "/a ", "/a/.", "/a/.."}) {
    EXPECT_FALSE(IsCanonicalStoragePath(path)) << path;
  }
  EXPECT_FALSE(IsCanonicalStoragePath("/" + std::string(256, 'a')));
  EXPECT_TRUE(IsCanonicalStoragePath("/" + std::string(255, 'a')));
}

TEST(PubkySessionCapabilitiesTest, Cover) {
  const std::vector<Capability> granted =
      *ParseCapabilities("/pub/notes/:rw,/priv/notes/:rwe");
  EXPECT_TRUE(CapabilitiesCover(granted, *ParseCapability("/pub/notes/a:rw")));
  EXPECT_TRUE(CapabilitiesCover(granted, *ParseCapability("/priv/notes/:e")));
  EXPECT_FALSE(CapabilitiesCover(granted, *ParseCapability("/pub/:r")));
  EXPECT_FALSE(CapabilitiesCover(granted, *ParseCapability("/pub/notes/:e")));
  EXPECT_FALSE(
      CapabilitiesCover(granted, *ParseCapability("/pub/notes-evil/:r")));
}

}  // namespace
}  // namespace pubky_session

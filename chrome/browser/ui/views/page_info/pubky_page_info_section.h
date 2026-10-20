// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_PAGE_INFO_PUBKY_PAGE_INFO_SECTION_H_
#define CHROME_BROWSER_UI_VIEWS_PAGE_INFO_PUBKY_PAGE_INFO_SECTION_H_

#include "base/memory/raw_ptr.h"
#include "ui/base/interaction/element_identifier.h"
#include "ui/base/metadata/metadata_header_macros.h"
#include "ui/views/view.h"
#include "url/origin.h"

class GURL;
class HostContentSettingsMap;

namespace content {
class WebContents;
}  // namespace content

// The "Pubky identity" section of page info: which identity the site uses,
// its access and since when, and a button that disconnects the site without
// touching other sites. Hidden when the site has no access.
class PubkyPageInfoSection : public views::View {
  METADATA_HEADER(PubkyPageInfoSection, views::View)

 public:
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kSectionElementId);
  DECLARE_CLASS_ELEMENT_IDENTIFIER_VALUE(kDisconnectElementId);

  PubkyPageInfoSection(content::WebContents* contents, const GURL& site_url);
  PubkyPageInfoSection(const PubkyPageInfoSection&) = delete;
  PubkyPageInfoSection& operator=(const PubkyPageInfoSection&) = delete;
  ~PubkyPageInfoSection() override;

 private:
  void Disconnect();

  raw_ptr<HostContentSettingsMap> settings_ = nullptr;
  const url::Origin origin_;
};

#endif  // CHROME_BROWSER_UI_VIEWS_PAGE_INFO_PUBKY_PAGE_INFO_SECTION_H_

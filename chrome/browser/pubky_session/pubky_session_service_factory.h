// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_SERVICE_FACTORY_H_
#define CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_SERVICE_FACTORY_H_

#include <memory>

#include "base/no_destructor.h"
#include "chrome/browser/profiles/profile_keyed_service_factory.h"

class Profile;

namespace pubky_session {
class PubkySessionService;
}  // namespace pubky_session

// One PubkySessionService per regular profile and per Incognito profile. The
// regular profile stores its session encrypted in the profile directory;
// Incognito keeps it in memory and revokes it when the profile ends.
class PubkySessionServiceFactory : public ProfileKeyedServiceFactory {
 public:
  static pubky_session::PubkySessionService* GetForProfile(Profile* profile);
  static PubkySessionServiceFactory* GetInstance();

  PubkySessionServiceFactory(const PubkySessionServiceFactory&) = delete;
  PubkySessionServiceFactory& operator=(const PubkySessionServiceFactory&) =
      delete;

 private:
  friend base::NoDestructor<PubkySessionServiceFactory>;

  PubkySessionServiceFactory();
  ~PubkySessionServiceFactory() override;

  // BrowserContextKeyedServiceFactory:
  std::unique_ptr<KeyedService> BuildServiceInstanceForBrowserContext(
      content::BrowserContext* context) const override;
};

#endif  // CHROME_BROWSER_PUBKY_SESSION_PUBKY_SESSION_SERVICE_FACTORY_H_

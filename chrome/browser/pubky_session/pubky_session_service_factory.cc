// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/pubky_session/pubky_session_service_factory.h"

#include "base/files/file_path.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/profiles/profile.h"
#include "components/pubky_session/pubky_session_service.h"
#include "components/pubky_session/session_store.h"
#include "content/public/browser/storage_partition.h"

// static
pubky_session::PubkySessionService* PubkySessionServiceFactory::GetForProfile(
    Profile* profile) {
  return static_cast<pubky_session::PubkySessionService*>(
      GetInstance()->GetServiceForBrowserContext(profile, /*create=*/true));
}

// static
PubkySessionServiceFactory* PubkySessionServiceFactory::GetInstance() {
  static base::NoDestructor<PubkySessionServiceFactory> instance;
  return instance.get();
}

PubkySessionServiceFactory::PubkySessionServiceFactory()
    : ProfileKeyedServiceFactory(
          "PubkySessionService",
          ProfileSelections::Builder()
              .WithRegular(ProfileSelection::kOwnInstance)
              .WithGuest(ProfileSelection::kNone)
              .WithSystem(ProfileSelection::kNone)
              .Build()) {}

PubkySessionServiceFactory::~PubkySessionServiceFactory() = default;

std::unique_ptr<KeyedService>
PubkySessionServiceFactory::BuildServiceInstanceForBrowserContext(
    content::BrowserContext* context) const {
  Profile* profile = Profile::FromBrowserContext(context);
  const base::FilePath storage_path =
      profile->IsOffTheRecord()
          ? base::FilePath()
          : profile->GetPath().AppendASCII(pubky_session::kStorageFileName);
  return std::make_unique<pubky_session::PubkySessionService>(
      profile->GetDefaultStoragePartition()
          ->GetURLLoaderFactoryForBrowserProcess(),
      g_browser_process->shared_url_loader_factory(),
      g_browser_process->os_crypt_async(), storage_path);
}

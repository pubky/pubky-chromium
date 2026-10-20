// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Talks to PubkyIdentityHandler for the "Pubky identity" page.
 */

import {sendWithPromise} from 'chrome://resources/js/cr.js';

export interface PubkySite {
  // The site's origin, to remove it.
  origin: string;
  // The origin as shown to the user.
  site: string;
  access: string;
  since: string;
}

export interface PubkyIdentity {
  // False in profiles without Pubky sessions, such as Guest.
  available: boolean;
  signedIn: boolean;
  // The rest is set only while signed in.
  expired?: boolean;
  name?: string;
  publicKey?: string;
  approval?: string;
  sites?: PubkySite[];
}

export interface PubkyBrowserProxy {
  /**
   * The current identity. Updates arrive as 'pubky-identity-changed'.
   */
  getPubkyIdentity(): Promise<PubkyIdentity>;

  /** Removes one site's access at once. */
  removePubkySite(origin: string): void;

  /** Revokes the browser's grant and forgets the identity. */
  signOutPubky(): void;
}

export class PubkyBrowserProxyImpl implements PubkyBrowserProxy {
  getPubkyIdentity() {
    return sendWithPromise<PubkyIdentity>('getPubkyIdentity');
  }

  removePubkySite(origin: string) {
    chrome.send('removePubkySite', [origin]);
  }

  signOutPubky() {
    chrome.send('signOutPubky');
  }

  static getInstance(): PubkyBrowserProxy {
    return instance || (instance = new PubkyBrowserProxyImpl());
  }

  static setInstance(obj: PubkyBrowserProxy) {
    instance = obj;
  }
}

let instance: PubkyBrowserProxy|null = null;

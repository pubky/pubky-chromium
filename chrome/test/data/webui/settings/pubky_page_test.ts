// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// clang-format off
import type {PubkyBrowserProxy, PubkyIdentity, SettingsPubkyPageElement} from 'chrome://settings/settings.js';
import {PubkyBrowserProxyImpl} from 'chrome://settings/settings.js';
import {webUIListenerCallback} from 'chrome://resources/js/cr.js';
import {assertEquals, assertFalse, assertTrue} from 'chrome://webui-test/chai_assert.js';
import {TestBrowserProxy} from 'chrome://webui-test/test_browser_proxy.js';
import {microtasksFinished} from 'chrome://webui-test/test_util.js';
// clang-format on

class TestPubkyBrowserProxy extends TestBrowserProxy implements
    PubkyBrowserProxy {
  identity: PubkyIdentity = {available: true, signedIn: false};

  constructor() {
    super(['getPubkyIdentity', 'removePubkySite', 'signOutPubky']);
  }

  getPubkyIdentity() {
    this.methodCalled('getPubkyIdentity');
    return Promise.resolve(this.identity);
  }

  removePubkySite(origin: string) {
    this.methodCalled('removePubkySite', origin);
  }

  signOutPubky() {
    this.methodCalled('signOutPubky');
  }
}

const SIGNED_IN: PubkyIdentity = {
  available: true,
  signedIn: true,
  expired: false,
  name: 'Marcos',
  publicKey: '8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty',
  approval: 'Approved by Pubky Ring · Read and write /pub/ · Homeserver 4msq…nowy',
  sites: [
    {
      origin: 'https://pubky.app',
      site: 'pubky.app',
      access: 'Read and write /pub/pubky.app/',
      since: 'Oct 20, 2026',
    },
    {
      origin: 'https://shop.pubky.app',
      site: 'shop.pubky.app',
      access: 'Read and write /pub/shop.pubky.app/',
      since: 'Oct 20, 2026',
    },
  ],
};

suite('PubkyPageTest', function() {
  let page: SettingsPubkyPageElement;
  let browserProxy: TestPubkyBrowserProxy;

  setup(function() {
    browserProxy = new TestPubkyBrowserProxy();
    PubkyBrowserProxyImpl.setInstance(browserProxy);
  });

  teardown(function() {
    page.remove();
  });

  async function initPage(identity: PubkyIdentity) {
    browserProxy.identity = identity;
    document.body.innerHTML = window.trustedTypes!.emptyHTML;
    page = document.createElement('settings-pubky-page');
    document.body.appendChild(page);
    await browserProxy.whenCalled('getPubkyIdentity');
    await microtasksFinished();
  }

  function query<T extends Element = HTMLElement>(selector: string): T|null {
    return page.shadowRoot!.querySelector<T>(selector);
  }

  test('ExplainsWhenUnavailable', async function() {
    await initPage({available: false, signedIn: false});
    assertTrue(!!query('#unavailable'));
    assertFalse(!!query('#identity'));
  });

  test('ExplainsSigningInWhenSignedOut', async function() {
    await initPage({available: true, signedIn: false});
    assertTrue(!!query('#signedOut'));
    assertFalse(!!query('#identity'));
    assertFalse(!!query('#signOut'));
  });

  test('ShowsTheIdentityAndItsSites', async function() {
    await initPage(SIGNED_IN);
    assertEquals('Marcos', query('#name')!.textContent!.trim());
    assertEquals(SIGNED_IN.publicKey, query('#publicKey')!.textContent!.trim());
    assertEquals(SIGNED_IN.approval, query('#approval')!.textContent!.trim());
    assertEquals('M', query('.avatar')!.textContent!.trim());

    const rows = page.shadowRoot!.querySelectorAll('.site-row');
    assertEquals(2, rows.length);
    assertEquals(
        'pubky.app', rows[0]!.querySelector('.site')!.textContent!.trim());
    assertEquals(
        'Read and write /pub/pubky.app/',
        rows[0]!.querySelector('.access')!.textContent!.trim());
    assertFalse(!!query('#noSites'));
  });

  test('RemovesASite', async function() {
    await initPage(SIGNED_IN);
    const rows = page.shadowRoot!.querySelectorAll('.site-row');
    rows[1]!.querySelector<HTMLElement>('.remove')!.click();
    assertEquals(
        'https://shop.pubky.app',
        await browserProxy.whenCalled('removePubkySite'));
  });

  test('FollowsUpdatesFromTheBrowser', async function() {
    await initPage(SIGNED_IN);
    webUIListenerCallback(
        'pubky-identity-changed', {...SIGNED_IN, sites: []});
    await microtasksFinished();
    assertEquals(0, page.shadowRoot!.querySelectorAll('.site-row').length);
    assertTrue(!!query('#noSites'));

    webUIListenerCallback(
        'pubky-identity-changed', {available: true, signedIn: false});
    await microtasksFinished();
    assertTrue(!!query('#signedOut'));
  });

  test('SignsOut', async function() {
    await initPage(SIGNED_IN);
    query('#signOut')!.click();
    await browserProxy.whenCalled('signOutPubky');
  });
});

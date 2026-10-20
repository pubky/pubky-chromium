// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * 'settings-pubky-page' shows the browser's Pubky identity and approval,
 * every site using it with its access, and sign-out. See pubky/SESSIONS.md.
 */
import 'chrome://resources/cr_elements/cr_button/cr_button.js';
import '../settings_page/settings_section.js';

import {CrLitElement} from '//resources/lit/v3_0/lit.rollup.js';
import {WebUiListenerMixinLit} from 'chrome://resources/cr_elements/web_ui_listener_mixin_lit.js';

import {getSearchManager} from '../search_settings.js';
import type {SettingsPlugin} from '../settings_main/settings_plugin.js';

import type {PubkyBrowserProxy, PubkyIdentity, PubkySite} from './pubky_browser_proxy.js';
import {PubkyBrowserProxyImpl} from './pubky_browser_proxy.js';
import {getCss} from './pubky_page.css.js';
import {getHtml} from './pubky_page.html.js';

const SettingsPubkyPageElementBase = WebUiListenerMixinLit(CrLitElement);

export class SettingsPubkyPageElement extends SettingsPubkyPageElementBase
    implements SettingsPlugin {
  static get is() {
    return 'settings-pubky-page';
  }

  static override get styles() {
    return getCss();
  }

  override render() {
    return getHtml.bind(this)();
  }

  static override get properties() {
    return {
      identity_: {type: Object},
    };
  }

  protected accessor identity_: PubkyIdentity = {
    available: true,
    signedIn: false,
  };

  private browserProxy_: PubkyBrowserProxy =
      PubkyBrowserProxyImpl.getInstance();

  override connectedCallback() {
    super.connectedCallback();
    this.addWebUiListener(
        'pubky-identity-changed', (identity: PubkyIdentity) => {
          this.identity_ = identity;
        });
    this.browserProxy_.getPubkyIdentity().then(identity => {
      this.identity_ = identity;
    });
  }

  protected getInitial_(): string {
    const name = this.identity_.name || '';
    return name ? name.charAt(0).toUpperCase() : '?';
  }

  protected getSites_(): PubkySite[] {
    return this.identity_.sites || [];
  }

  protected onCopyKeyClick_() {
    navigator.clipboard.writeText(this.identity_.publicKey || '');
  }

  protected onRemoveSiteClick_(e: Event) {
    const origin = (e.currentTarget as HTMLElement).dataset['origin'];
    if (origin) {
      this.browserProxy_.removePubkySite(origin);
    }
  }

  protected onSignOutClick_() {
    this.browserProxy_.signOutPubky();
  }

  // SettingsPlugin implementation
  async searchContents(query: string) {
    const searchRequest = await getSearchManager().search(query, this);
    return searchRequest.getSearchResult();
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'settings-pubky-page': SettingsPubkyPageElement;
  }
}

customElements.define(SettingsPubkyPageElement.is, SettingsPubkyPageElement);

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {html} from '//resources/lit/v3_0/lit.rollup.js';

import type {SettingsPubkyPageElement} from './pubky_page.js';

export function getHtml(this: SettingsPubkyPageElement) {
  // clang-format off
  return html`<!--_html_template_start_-->
<settings-section page-title="$i18n{pubkyPageTitle}"
    class="cr-centered-card-container">
  ${!this.identity_.available ? html`
    <div class="cr-row first">
      <div class="cr-padded-text" id="unavailable">$i18n{pubkyUnavailable}</div>
    </div>
  ` : html`${!this.identity_.signedIn ? html`
    <div class="cr-row first">
      <div class="cr-padded-text" id="signedOut">$i18n{pubkySignedOut}</div>
    </div>
  ` : html`
    <div class="cr-row first" id="identity">
      <div class="avatar" aria-hidden="true">${this.getInitial_()}</div>
      <div class="flex cr-padded-text">
        <div id="name">${this.identity_.name}</div>
        <div class="secondary" id="publicKey">${this.identity_.publicKey}</div>
        <div class="secondary" id="approval">${this.identity_.approval}</div>
      </div>
      <cr-button id="copyKey" @click="${this.onCopyKeyClick_}">
        $i18n{pubkyCopyKey}
      </cr-button>
    </div>
    <div class="cr-row">
      <h2 class="flex">$i18n{pubkySites}</h2>
    </div>
    ${this.getSites_().length === 0 ? html`
      <div class="list-frame">
        <div class="list-item secondary" id="noSites">$i18n{pubkyNoSites}</div>
      </div>
    ` : html`
      <div class="list-frame" id="sites">
        <div class="list-item column-header">
          <div class="site">$i18n{pubkySiteColumn}</div>
          <div class="access">$i18n{pubkyAccessColumn}</div>
          <div class="since">$i18n{pubkySinceColumn}</div>
          <div class="remove"></div>
        </div>
        ${this.getSites_().map(site => html`
          <div class="list-item site-row">
            <div class="site">${site.site}</div>
            <div class="access secondary">${site.access}</div>
            <div class="since secondary">${site.since}</div>
            <cr-button class="remove" data-origin="${site.origin}"
                aria-label="${this.i18n('pubkyRemoveSiteAriaLabel', site.site)}"
                @click="${this.onRemoveSiteClick_}">
              $i18n{pubkyRemoveSite}
            </cr-button>
          </div>
        `)}
      </div>
    `}
    <div class="cr-row" id="signOutRow">
      <div class="flex cr-padded-text">
        <div>$i18n{pubkySignOutTitle}</div>
        <div class="secondary">$i18n{pubkySignOutBody}</div>
      </div>
      <cr-button id="signOut" @click="${this.onSignOutClick_}">
        $i18n{pubkySignOutButton}
      </cr-button>
    </div>
  `}`}
</settings-section>
<!--_html_template_end_-->`;
  // clang-format on
}

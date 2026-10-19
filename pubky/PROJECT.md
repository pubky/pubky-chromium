# Pubky Chromium project

Status: S0 foundations complete (October 2026). This document records the approved operating boundaries.

## Product and first milestone

Build on the existing Pubky Chromium fork. The long-term goal is native Pubky identity and scoped sessions, with public-key navigation, authenticated connections, and identity UI. The immediate milestone is a reproducible Linux baseline and an evidence-backed map of the remaining work. No session storage, authenticated writes, replacement of existing browsing protections, mobile implementation, release signing, or new resolver implementation is authorized in this first milestone.

Repository: `pubky/pubky-chromium`, development branch `pubky`.

Adopted source revision: `77445742d82c8cfc482b2fea0476fe5f84d16032` from `SeverinAlexB/pubky-chromium`. Its recorded Chromium base is `7fec6741f4f7ea010205dc20afc7dafb90221176`. Keep the inherited `DEPS` and `pubky/depot-tools-revision.txt` pins until an approved update. Preserve Chromium branding/licensing restrictions and third-party notices.

The inherited project documents macOS ARM64 results in `pubky/VERIFICATION.md`. Those are the source author's results, not independent Linux validation by this project. The current `navigator.pubky` interface reports built-in capabilities; it is not a privileged session API.

## Scope and standing approvals

- Autonomous work is limited to this fork and explicitly approved goals. Before any repository action outside this fork, request owner approval naming the repository, purpose, and actions. Record possible external dependencies here or in this project's issues; do not open external issues, comments, branches, or PRs without permission.
- An approved assignment carries these standing approvals: a branch off `pubky` named `s0/<issue-or-topic>-<description>`, the tests that apply to the change, and a pull request against `pubky`. Do not ask for them again. Everything else in this list still needs the owner.
- Work reaches an engineer in one of two ways. While the owner is online, the owner or the architect assigns it directly in chat. For work queued while the owner is away, the owner labels an issue `ready` plus `mini-1` or `mini-2`; the queue sync sets `in-progress`, and the engineer's result moves it to `review` (waiting for the owner) or `blocked` (stopped after two failed attempts, with the reason in a comment). Either way the result is a pull request with one handoff comment.
- Questions and exploratory ideas are discussion, not authorization. New product, protocol, architecture, security, or privacy decisions go to the owner with a recommendation and alternatives.
- No new paid infrastructure, releases, deployment, or credential sharing is authorized. Use existing resources within their approved limits.
- Internal conversations and private source material must not be copied into public issues, commits, or artifacts. Public claims need public evidence or explicit disclosure approval.

## Target platforms and build gate

Linux x86_64 is the initial reproduction target on the designated Linux builder. A resource-capped trial there is approved; the previous cloud-only assumption is superseded. No cloud purchase is approved. macOS remains an inherited, unverified-by-us platform; macOS-specific changes need actual macOS validation. Windows is part of the first milestone; Windows-specific changes need Windows validation before a release. Mobile is outside the first milestone.

Each engineer works in its own checkout on its own machine. Builds run on the designated builder in one shared, persistent build folder under its host lock, one at a time; never start from an empty build folder. Running `gclient sync` or changing dependency pins needs the owner, except for the upstream syncs that [Upstream Chromium updates](#upstream-chromium-updates) allows. Never delete or clean an `out/` directory.

The inherited `pubky/args.gn`, `pubky/gclient.py`, and scripts target macOS ARM64 and use `caffeinate`. Do not run them on Linux as if they were validated Linux commands.

Release checks to preserve:

- `net_unittests`, focused filter: `SSLClientSocketTest.Pubky*:HttpResponseInfoTest.*:DnsResponseResultExtractorTest.*:HostCacheTest.Pubky*:DnsTransactionTest.Pubky*:HostResolverManagerTest.Pubky*`.
- `third_party/blink/renderer/platform:pubky_browser_unittests` and its produced `pubky_browser_unittests` executable.
- Pubky capability web-platform tests described in `pubky/scripts/test_capabilities.sh`.
- Live public-key navigation, deliberate wrong-key rejection, and ordinary HTTPS browsing, without DNS/TLS bypass flags.

Testing has three levels. Every pull request runs the checks that need no Chromium build, for example Python tests and `PRESUBMIT_test.py`. A pull request or review that touches C++ also builds incrementally in the shared build folder: the changed files (`autoninja -C <output> ../../<path>.cc^`) and the focused test target, then runs the relevant tests with `--gtest_filter`. Check the plan first with `autoninja -n`; if it exceeds about 5,000 steps (roughly an hour at four jobs), record the step count and skip the build. A full build and the release checks above run only when preparing a release. Record the commands, the revision, and the results in the handoff comment.

## Branches, review, and integration

Use one branch per issue, based on the pinned development branch, named `s0/<issue-number>-<description>` for foundation work. Give each implementation an isolated writable workspace. Do not force-push or change inherited dependency pins as incidental cleanup. Upstream Chromium updates follow the next section; there are no automatic upstream merges.

An issue is Ready only when its goal, boundaries, dependencies, acceptance checks, and approval context are sufficient to execute. Independent work can proceed in parallel. Shared protocol/interface changes, dependency upgrades, broad refactors, and builds must be coordinated; review takes priority over starting another implementation.

Authors self-review and exercise the behavior they changed. The owner reviews and merges pull requests; a second engineer reviews only when the owner labels the PR `ready` with the other machine's label. New commits invalidate affected review evidence. Integration is sequential, with dependent changes checked against the new base.

Engineers do not merge. Documentation-only pull requests merge without review. Missing CI is not evidence of a pass. Documentation-only changes must not claim unrun builds. Do not waive failures or weaken tests to make progress. Stop after two failed attempts or two unsuccessful review/repair cycles and report the failure and what can continue.

Engineers share one GitHub account, so a review comment names the reviewing engineer and the exact commit. Findings, author replies, and decisions belong on the PR.

## Upstream Chromium updates

Decided in #54 (October 2026), after a rehearsal that rebased `pubky` onto Chromium 156.0.8078.43. The measurements are in that issue.

The fork follows Chromium's Extended Stable releases. Chromium ships a stable milestone every two weeks and stops patching the previous one when it does. Extended Stable stays on every fourth milestone (152, then 156) and keeps receiving security fixes until the next one replaces it, about eight weeks later. Google ships Extended Stable only for Windows and macOS, but the release tags build on Linux too.

- **Base.** A release tag from the milestone's branch, `<milestone>.0.<branch>.<patch>`, never `main`. A `main` snapshot such as 156.0.8073.0 never receives security fixes. `upstream-revision.txt` records the commit of the tag in use.
- **Security updates.** Merge each Extended Stable release of the current milestone and have the release ready for signing within seven days, or within three days when Chrome's release notes say a fixed vulnerability is exploited in the wild. Expected cost: zero or one conflicting file, a few `DEPS` changes, an incremental build per platform (not measured yet; the week from 156.0.8078.36 to .43 changed 284 files) and the release checks.
- **Milestone syncs.** When Extended Stable moves to a new milestone (next expected: 160, in January 2027), move the fork within two weeks. Expected cost: 80 to 90 conflicting files, most of them resolved by rule, a full rebuild per platform (three hours on Linux for `chrome` and the test targets at 8 to 12 jobs; the first macOS and Windows builds took about seven hours each), the release checks and a release.
- **Merge, do not rebase.** On a branch off `pubky` named `s0/<issue>-chromium-<version>`, `git merge` the tag, resolve the conflicts, run `gclient sync`, build, run the release checks and open a pull request against `pubky`. `pubky` is never rewritten, so every released source revision stays reachable. The rehearsal replayed the fork's 28 merged pull requests onto the new tag (four conflict stops) and also merged the tag in one step (one stop). Both gave the same files, apart from the order of lines that both sides added in 81 of them.
- **Conflicts.** The `chromium_strings_*.xtb` files and `tools/traffic_annotation/summary/{annotations,grouping}.xml` conflict on every sync because both sides add lines next to each other. Keep both sides, then check that no id appears twice. Resolve the rest by hand; in the rehearsal that was two GN lists and one changed annotation hash.
- **Approvals.** A sync that follows this section is approved to run `gclient sync` in the shared build folder and to take upstream's `DEPS` pins, plus a newer depot_tools revision if upstream requires one. Pinning a dependency to anything other than upstream's revision still needs the owner, and so does each release.

## S0 acceptance ledger

S0 closed in October 2026. Final state of each gate:

| Gate | Current state |
|---|---|
| Mission, exclusions, repository, first platform and operating permissions | Recorded here |
| Base adoption, source/tool pins, patch scope, licensing, update policy and maintenance-cost evidence | Pins adopted; licensing ships with each release; upstream sync policy in [Upstream Chromium updates](#upstream-chromium-updates), rebase cost measured in #54 |
| Identifier grammar: PKD sites versus Pubky identities, search/fallback, malformed/Unicode input | Recorded in [IDENTIFIERS.md](IDENTIFIERS.md) |
| TLS trust model: key binding, secure context, downgrade, mixed content, connection display | Recorded in [TLS_TRUST_MODEL.md](TLS_TRUST_MODEL.md), assuming PKResolve resolution and delegation |
| Profile/avatar lookup and privacy defaults | Settled before identity-card work starts; no new lookups implemented |
| Scoped-session design brief and origin-permission/XSS analysis | Settled before session-layer work starts |
| Threat model | Initial version in [THREAT_MODEL.md](THREAT_MODEL.md); each feature adds its section before it ships |
| Google-service inventory/replacement policy | Idle Google requests reduced (#45); the full inventory continues as hardening work (T17 in [THREAT_MODEL.md](THREAT_MODEL.md)) |
| Linux checkout/build isolation, resource/access limits, first-fetch runbook/evidence | Done: the designated builder produces every release |
| Dependency ledger and protocol/state-machine review | Recorded before each implementation that adds a dependency or a protocol state machine |

Preserve the original roadmap's substantive gates. Record an explicit amendment when a previous environment assumption is replaced; do not silently mark an unmeasured or unavailable gate complete.

Amendment, October 2026: the project is experimental, so design gates no longer block all runtime work up front. Each gate is settled before the implementation that depends on it, as the table states. Prototypes may proceed behind a flag before then.

The public issues hold actionable work and sanitized evidence. The private planning board can hold decision requests and future work, but does not make linked public issues private. Later roadmap stages remain high-level planning items until their scope is approved.

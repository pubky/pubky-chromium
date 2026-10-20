# Agent instructions

Read `pubky/PROJECT.md` for the approved scope and the standing approvals. Read the assigned issue or PR in full before changing code.

- Work only on this fork, `pubky/pubky-chromium`, on the assigned goal, whether it came as an issue or as a direct assignment. Any action outside the fork needs the owner's approval first.
- The standing approvals in PROJECT.md cover routine work: a branch per issue, the tests that apply, and pull requests. Do not ask for them again. Build only incrementally in the shared build folder, within about an hour; full builds are for releases.
- Make the smallest correct change and reuse existing code. Verify the behavior you changed; do not re-verify what the issue or PR already records. Never weaken tests or security controls to pass a check.
- Integrate directly. No feature flags, kill switches, dual code paths, backwards-compatibility shims or migration precautions unless the issue asks for one. Replace the old path instead of running both.
- No security audits before production. One audit of everything happens before the production release; do not request or wait for one.
- Stop after two failed attempts at the same step. Report the exact error and what is left instead of retrying in a loop.
- Hand off with one comment on the issue or PR: PR link, what changed, what tests ran, and what is left. Keep private team details, infrastructure paths, and credentials out of public changes.
- Decisions on scope, architecture, protocol, security, privacy, spending, or release go to the owner with a recommendation and alternatives.

# extverify

Verify-before-install for agent extensions. One command, one verdict (`ALLOW`, `DENY`, or `REVIEW`) **before** you install an extension into your editor — because on 29/10/2026 a trojanized "Claude Code" extension rode Cursor's marketplace for 11 hours and reached ≤5,000 users.

![Demo: DENY a recorded 29/10-shaped listing, REVIEW a real extension](demo/extverify-demo.gif)

The demo is rendered from the real CLI transcript in [demo/transcript.txt](demo/transcript.txt).

## The problem

Your coding agent runs code, reads private repos, sends mail. Its extensions are an execution surface — but nobody checks the **listing** before install:

- Marketplaces verify publisher *identity* (badges), not *safety*. A verified badge never meant "code audited".
- Registries react with takedowns **after** distribution. The 29/10 payload (SSH key appended to `~/.ssh/authorized_keys`, reverse tunnel, OS persistence) shipped for 11 hours first.
- The 29/10 attack didn't even need typosquatting: it served **wrong bytes under the right identifier** (`Anthropic.claude-code` 2.1.312/2.1.313), and only on one distribution path. Identity checks alone would have passed it.

## What it checks

| Check | What it finds |
|---|---|
| `publisher-name-squat` (high) | Publisher name within edit distance 2 of a known publisher (e.g. `ms-pyth0n`) |
| `download-velocity-anomaly` (high) | Explosive installs on a young publisher (<90d) — the fake-listing shape |
| `cross-registry-hash-mismatch` (medium) | Same version, different bytes on VS Marketplace vs Open VSX — registries disagree |
| `version-repackaged` (high) | Same version, different bytes than your local pin |
| `publisher-too-new` (medium) | Publisher first published <30 days ago |
| `runs-on-startup` (medium) | `activationEvents` includes `*` / `onStartupFinished` |
| `bundled-binary` (medium) | VSIX ships executables |
| `installs-no-ratings` (medium) | 1,000+ installs, 0 ratings |
| `publisher-unverified` / `single-registry` / `vsix-too-large` (low) | Informational |

Any `high` finding → `DENY`. Otherwise any finding → `REVIEW`. No findings → `ALLOW`.
Every finding carries the exact evidence string it matched. The JSON manifest makes the verdict re-checkable without re-running anything.

## Usage

```bash
npx extverify verify esbenp.prettier-vscode
# REVIEW  esbenp.prettier-vscode@12.4.0
#   [medium] runs-on-startup: activationEvents includes "onStartupFinished" ...

npx extverify verify some-publisher.shiny-tool --json   # machine-readable
npx extverify pin esbenp.prettier-vscode@12.4.0          # pin this version's hash
npx extverify unpin esbenp.prettier-vscode@12.4.0
```

Exit codes: `0` = ALLOW/REVIEW, `1` = DENY, `2` = usage/error.

## Honest limits

- **Cannot catch a compromised long-trusted publisher account** pushing clean-looking bytes — it checks anomaly, not account takeover.
- **Cannot catch behaviorally-obfuscated malware** (see Socket's GlassWorm research): this is a listing/manifest checker, not a code-behavior analyzer. For deep analysis use Socket.dev.
- **A warning can be ignored** — the tool only works if your agent is wired to call it before install (same model as vetgate, our sibling pre-install gate for npm packages / Actions / scripts: different detection domain, complementary).
- **Marketplace APIs change** — checked against the public gallery API + Open VSX API on 2026-11-04; the tool reports `rulesVersion` so verdicts stay re-checkable.
- **mcp-audit** already scans *installed* IDE extensions (post-install inventory, broader). extverify is the *pre-install* identity + marketplace-signals + hash-pinning gate. Different moment, complementary.

## Install

Requires Node ≥20. Zero runtime dependencies.

```bash
npm install -g extverify   # after npm publish (pending)
# or from source:
git clone https://github.com/techdevfun/extverify && cd extverify && npm ci && npm run build
```

## Name note

`gradence100/extverify` exists on GitHub (0 stars, untouched since 2026-06-01, verifies GitHub repo presence — different domain). npm name `extverify` was free at check time (2026-11-04).

## License

MIT

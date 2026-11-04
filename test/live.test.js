/**
 * Live smoke: runs the real CLI against the real registries.
 * Soft-skips (exit 0, "SKIP") when the network/registries are unreachable —
 * CI must stay green even if a registry has a bad day. A hard failure here
 * means the product's core path broke, not the network.
 *
 * Run with: node --test test/live.test.js
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

function tryRun(args) {
  try {
    const out = execFileSync("node", [CLI, ...args], {
      encoding: "utf8",
      timeout: 90000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, code: 0, out };
  } catch (e) {
    // execFileSync throws on non-zero exit; CLI uses 1=DENY (a verdict, not a crash)
    if (e.status === 1) return { ok: true, code: 1, out: e.stdout?.toString() ?? "" };
    return { ok: false, code: e.status ?? -1, err: e.stderr?.toString() ?? String(e) };
  }
}

async function networkUp() {
  try {
    const r = await fetch("https://open-vsx.org/api/", { signal: AbortSignal.timeout(15000) });
    return r.ok;
  } catch {
    return false;
  }
}

describe("live smoke (real registries)", async () => {
  const up = await networkUp();
  it("verify esbenp.prettier-vscode returns a verdict (not a crash)", { skip: !up && "offline" }, () => {
    const r = tryRun(["verify", "esbenp.prettier-vscode"]);
    assert.ok(r.ok, `CLI crashed: ${r.err}`);
    assert.ok(/^(ALLOW|DENY|REVIEW)/.test(r.out), `no verdict in output: ${r.out.slice(0, 120)}`);
    assert.ok(r.out.includes("esbenp.prettier-vscode@"), "version missing from output");
  });
  it("verify --json emits a re-checkable manifest", { skip: !up && "offline" }, () => {
    const r = tryRun(["verify", "esbenp.prettier-vscode", "--json"]);
    assert.ok(r.ok, `CLI crashed: ${r.err}`);
    const rep = JSON.parse(r.out);
    assert.ok(["ALLOW", "DENY", "REVIEW"].includes(rep.verdict));
    assert.ok(rep.manifest?.rulesVersion, "manifest.rulesVersion missing");
    assert.ok(Array.isArray(rep.findings), "findings not an array");
    assert.ok(rep.extension?.sha256?.length === 64, "sha256 missing");
  });
  it("unknown extension errors cleanly (exit 2, no stack)", { skip: !up && "offline" }, () => {
    const r = tryRun(["verify", "no-such-publisher-xyz.no-such-ext-xyz"]);
    assert.ok(!r.ok && r.code === 2, `expected exit 2, got ${r.code}: ${r.err?.slice(0, 120)}`);
  });
});

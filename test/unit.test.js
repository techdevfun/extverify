/** Unit tests: pure functions (no network). Run with: node --test test/*.test.js */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  decide,
  detectSquat,
  levenshtein,
  publisherAgeDays,
  runRules,
} from "../dist/rules.js";
import { listEntries, readEntry, readPackageJson } from "../dist/zip.js";
import { parseExtensionId } from "../dist/market.js";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

describe("parseExtensionId", () => {
  it("parses publisher.name", () => {
    assert.deepEqual(parseExtensionId("ms-python.python"), {
      publisher: "ms-python",
      name: "python",
      version: undefined,
    });
  });
  it("parses publisher.name@version", () => {
    assert.deepEqual(parseExtensionId("a.b@1.2.3"), {
      publisher: "a",
      name: "b",
      version: "1.2.3",
    });
  });
  it("rejects garbage", () => {
    assert.throws(() => parseExtensionId("not an id!!"), /bad extension id/);
    assert.throws(() => parseExtensionId("a"), /bad extension id/);
  });
});

describe("levenshtein", () => {
  it("distance 1 for single substitution", () => {
    assert.equal(levenshtein("ms-python", "ms-pyth0n"), 1);
  });
  it("distance 0 for equal", () => {
    assert.equal(levenshtein("github", "github"), 0);
  });
});

describe("detectSquat", () => {
  it("flags near-miss of known publisher", () => {
    assert.equal(detectSquat("ms-pyth0n"), "ms-python");
  });
  it("passes exact known publisher", () => {
    assert.equal(detectSquat("ms-python"), null);
  });
  it("passes unrelated names", () => {
    assert.equal(detectSquat("some-random-dev"), null);
  });
});

describe("publisherAgeDays", () => {
  it("computes days from publishedDate", () => {
    const ext = { publishedDate: "2026-10-01T00:00:00Z" };
    const age = publisherAgeDays(ext, Date.parse("2026-11-04T00:00:00Z"));
    assert.ok(age !== null && Math.abs(age - 34) < 0.01, `age=${age}`);
  });
  it("null when missing", () => {
    assert.equal(publisherAgeDays({}), null);
  });
});

function fakeExt(over = {}) {
  return {
    publisher: { publisherName: "acme", displayName: "Acme", isVerified: true },
    extensionName: "thing",
    displayName: "Thing",
    shortDescription: "",
    statistics: { install: 100, ratingcount: 5 },
    versions: [{ version: "1.0.0", lastUpdated: "", files: [] }],
    ...over,
  };
}
function baseCtx(over = {}) {
  return {
    ext: fakeExt(),
    publisherAgeDays: 400,
    velocityPerDay: 1,
    manifest: { activationEvents: ["onLanguage:python"], contributes: { commands: [] } },
    bundledBinaries: [],
    pinnedSha256: null,
    actualSha256: null,
    squatTarget: null,
    manifestSkipped: false,
    crossRegistry: "match",
    ...over,
  };
}

describe("runRules", () => {
  it("clean extension -> no findings -> ALLOW", () => {
    const f = runRules(baseCtx());
    assert.deepEqual(f, []);
    assert.equal(decide(f), "ALLOW");
  });
  it("name squat -> high -> DENY", () => {
    const f = runRules(baseCtx({ squatTarget: "ms-python" }));
    assert.ok(f.some((x) => x.rule === "publisher-name-squat" && x.severity === "high"));
    assert.equal(decide(f), "DENY");
  });
  it("velocity anomaly -> high -> DENY (the 29/10 fake-extension shape)", () => {
    const f = runRules(
      baseCtx({
        ext: fakeExt({ statistics: { install: 5000, ratingcount: 0 } }),
        publisherAgeDays: 0.5,
        velocityPerDay: 10000,
      }),
    );
    assert.ok(f.some((x) => x.rule === "download-velocity-anomaly"));
    assert.equal(decide(f), "DENY");
  });
  it("startup activation + binary -> REVIEW", () => {
    const f = runRules(
      baseCtx({
        manifest: { activationEvents: ["*"], contributes: { commands: [] } },
        bundledBinaries: ["extension/bin/helper"],
      }),
    );
    assert.ok(f.some((x) => x.rule === "runs-on-startup"));
    assert.ok(f.some((x) => x.rule === "bundled-binary"));
    assert.equal(decide(f), "REVIEW");
  });
  it("repackaged version vs pin -> high -> DENY", () => {
    const f = runRules(baseCtx({ pinnedSha256: "aaa", actualSha256: "bbb" }));
    assert.ok(f.some((x) => x.rule === "version-repackaged"));
    assert.equal(decide(f), "DENY");
  });
  it("new publisher (<30d) -> medium finding", () => {
    const f = runRules(baseCtx({ publisherAgeDays: 5 }));
    assert.ok(f.some((x) => x.rule === "publisher-too-new"));
    assert.equal(decide(f), "REVIEW");
  });
  it("skipped manifest -> low vsix-too-large finding", () => {
    const f = runRules(baseCtx({ manifestSkipped: true, manifest: null }));
    assert.ok(f.some((x) => x.rule === "vsix-too-large" && x.severity === "low"));
    assert.equal(decide(f), "REVIEW");
  });
  it("old publisher + high sustained installs -> NO velocity finding (prettier shape)", () => {
    const f = runRules(
      baseCtx({
        ext: fakeExt({ statistics: { install: 72735853, ratingcount: 40000 } }),
        publisherAgeDays: 3584,
        velocityPerDay: 20291,
      }),
    );
    assert.ok(!f.some((x) => x.rule === "download-velocity-anomaly"));
  });
  it("cross-registry mismatch -> medium -> REVIEW (registries can legitimately repackage)", () => {
    const f = runRules(baseCtx({ crossRegistry: "mismatch" }));
    const hit = f.find((x) => x.rule === "cross-registry-hash-mismatch");
    assert.ok(hit && hit.severity === "medium");
    assert.equal(decide(f), "REVIEW");
  });
  it("cross-registry match -> no finding from that rule", () => {
    const f = runRules(baseCtx({ crossRegistry: "match" }));
    assert.ok(!f.some((x) => x.rule.startsWith("cross-registry")));
  });
});

describe("zip reader (crafted in-memory zip)", () => {
  function makeZip() {
    // build a minimal stored (method 0) zip with one file: extension/package.json
    const payload = Buffer.from(JSON.stringify({ name: "x", activationEvents: ["*"] }));
    const fname = Buffer.from("extension/package.json");
    const local = Buffer.alloc(30 + fname.length + payload.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8); // method 0 = stored
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(payload.length, 22);
    local.writeUInt16LE(fname.length, 26);
    fname.copy(local, 30);
    payload.copy(local, 30 + fname.length);
    const cd = Buffer.alloc(46 + fname.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt32LE(payload.length, 20);
    cd.writeUInt32LE(payload.length, 24);
    cd.writeUInt16LE(fname.length, 28);
    cd.writeUInt32LE(0, 42);
    fname.copy(cd, 46);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(1, 8);
    eocd.writeUInt16LE(1, 10);
    eocd.writeUInt32LE(cd.length, 12);
    eocd.writeUInt32LE(local.length, 16);
    return Buffer.concat([local, cd, eocd]);
  }
  it("lists and reads the entry", () => {
    const buf = makeZip();
    const entries = listEntries(buf);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "extension/package.json");
    const data = readEntry(buf, entries[0]);
    assert.deepEqual(JSON.parse(data.toString()), { name: "x", activationEvents: ["*"] });
  });
  it("readPackageJson finds extension/package.json", () => {
    const m = readPackageJson(makeZip());
    assert.ok(m && m.name === "x");
  });
  it("rejects non-zip", () => {
    assert.throws(() => listEntries(Buffer.from("hello")), /not a zip/);
  });
  it("inflates DEFLATE (method 8) entries — the path real VSIXes use", () => {
    const payload = Buffer.from(
      JSON.stringify({ name: "y", version: "1.0.0", padding: "x".repeat(2000) }),
    );
    const deflated = deflateRawSync(payload);
    const fname = Buffer.from("extension/package.json");
    const local = Buffer.alloc(30 + fname.length + deflated.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8); // method 8 = deflate
    local.writeUInt32LE(deflated.length, 18);
    local.writeUInt32LE(payload.length, 22);
    local.writeUInt16LE(fname.length, 26);
    fname.copy(local, 30);
    deflated.copy(local, 30 + fname.length);
    const cd = Buffer.alloc(46 + fname.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(8, 10);
    cd.writeUInt32LE(deflated.length, 20);
    cd.writeUInt32LE(payload.length, 24);
    cd.writeUInt16LE(fname.length, 28);
    cd.writeUInt32LE(0, 42);
    fname.copy(cd, 46);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(1, 8);
    eocd.writeUInt16LE(1, 10);
    eocd.writeUInt32LE(cd.length, 12);
    eocd.writeUInt32LE(local.length, 16);
    const buf = Buffer.concat([local, cd, eocd]);
    const entries = listEntries(buf);
    assert.equal(entries[0].method, 8);
    const data = readEntry(buf, entries[0]);
    assert.deepEqual(JSON.parse(data.toString()).name, "y");
    const m = readPackageJson(buf);
    assert.ok(m && m.name === "y");
  });
});

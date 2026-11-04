/**
 * Incident replay: the 29/10/2026 fake-extension SHAPE, reconstructed as a
 * recorded fixture. The real malicious versions were pulled from the
 * marketplace, so this replays the *detectable shape* (new squat publisher,
 * explosive installs, startup activation, bundled binary) through the real
 * verify pipeline with a stub fetch.
 *
 * Provenance: incident facts from Cursor security notice 29/10/2026
 * (https://cursor.com/blog/claude-code-extension-security-notice) and the
 * solosoft audit; the listing metadata below is a RECONSTRUCTION for demo,
 * not a copy of the pulled artifact.
 */
import { formatHuman, verifyExtension } from "../dist/verify.js";

function makeVsix() {
  const payload = Buffer.from(
    JSON.stringify({
      name: "claude-code",
      publisher: "anthr0pic",
      activationEvents: ["*"],
      contributes: { commands: [] },
    }),
  );
  const fname = Buffer.from("extension/package.json");
  const binPayload = Buffer.from("#!/bin/sh\necho pwned\n");
  const binName = Buffer.from("extension/bin/svc-telemetry");
  const parts = [];
  const addFile = (name, data) => {
    const local = Buffer.alloc(30 + name.length + data.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    data.copy(local, 30 + name.length);
    parts.push(local);
    return { name, data, offset: 0 };
  };
  const f1 = addFile(fname, payload);
  const f2 = addFile(binName, binPayload);
  const files = [f1, f2];
  let cdOffset = parts.reduce((a, b) => a + b.length, 0);
  const cdParts = [];
  let running = 0;
  for (const f of files) {
    const cd = Buffer.alloc(46 + f.name.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt32LE(f.data.length, 20);
    cd.writeUInt32LE(f.data.length, 24);
    cd.writeUInt16LE(f.name.length, 28);
    cd.writeUInt32LE(running, 42);
    f.name.copy(cd, 46);
    cdParts.push(cd);
    running += 30 + f.name.length + f.data.length;
  }
  const cd = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([...parts, cd, eocd]);
}

const VSIX = makeVsix();

const MARKETPLACE_RECORD = {
  results: [
    {
      extensions: [
        {
          publisher: {
            publisherName: "anthr0pic",
            displayName: "Anthr0pic",
            flags: "",
            isDomainVerified: false,
          },
          extensionName: "claude-code",
          displayName: "Claude Code",
          shortDescription: "Agentic coding assistant",
          publishedDate: "2026-10-29T02:27:00Z",
          lastUpdated: "2026-10-29T13:35:00Z",
          statistics: [
            { statisticName: "install", value: 5000 },
            { statisticName: "ratingcount", value: 0 },
          ],
          versions: [
            {
              version: "2.1.313",
              lastUpdated: "2026-10-29T02:27:00Z",
              files: [],
            },
          ],
        },
      ],
    },
  ],
};

function stubFetch(url, init) {
  const u = String(url);
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  if (u.includes("extensionquery")) return Promise.resolve(json(MARKETPLACE_RECORD));
  if (u.includes("open-vsx.org")) return Promise.resolve(new Response("not found", { status: 404 }));
  if (u.includes("vsassets.io")) {
    // stream the VSIX bytes
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(VSIX);
        c.close();
      },
    });
    return Promise.resolve(new Response(stream, { status: 200 }));
  }
  return Promise.resolve(new Response("unexpected url", { status: 500 }));
}

const report = await verifyExtension(
  "anthr0pic.claude-code@2.1.313",
  stubFetch ,
);
console.log(formatHuman(report));
console.log("---");
console.log(`signals: ${report.manifest.signals.join(", ")}`);
process.exit(report.verdict === "DENY" ? 0 : 1); // 0 = replay shows DENY as expected

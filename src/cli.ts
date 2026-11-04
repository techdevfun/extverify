#!/usr/bin/env node
/**
 * extverify — verify-before-install for agent extensions.
 * Usage:
 *   extverify verify <publisher.name[@version]> [--json]
 *   extverify pin    <publisher.name[@version]>
 *   extverify unpin  <publisher.name@version>
 */
import { fetchExtension, parseExtensionId, vsixDownloadUrl } from "./market.js";
import { hashRemoteVsix } from "./openvsx.js";
import { delPin, setPin } from "./pin.js";
import { formatHuman, verifyExtension } from "./verify.js";

function usage(): never {
  console.error(
    "usage:\n" +
      "  extverify verify <publisher.name[@version]> [--json]\n" +
      "  extverify pin    <publisher.name[@version]>\n" +
      "  extverify unpin  <publisher.name@version>",
  );
  process.exit(2);
}

async function cmdVerify(id: string, asJson: boolean): Promise<void> {
  const report = await verifyExtension(id);
  if (asJson) console.log(JSON.stringify(report, null, 2));
  else console.log(formatHuman(report));
  process.exit(report.verdict === "DENY" ? 1 : 0);
}

async function cmdPin(id: string): Promise<void> {
  const { publisher, name, version } = parseExtensionId(id);
  const ext = await fetchExtension(publisher, name);
  const ver = version ?? ext.versions[0]?.version;
  if (!ver) throw new Error("marketplace returned no versions");
  // Pin the MS-marketplace bytes (the primary install source for most users).
  const sha256 = await hashRemoteVsix(vsixDownloadUrl(publisher, name, ver));
  setPin(`${publisher}.${name}@${ver}`, sha256);
  console.log(`pinned ${publisher}.${name}@${ver}  sha256:${sha256.slice(0, 16)}…`);
}

async function cmdUnpin(id: string): Promise<void> {
  const { publisher, name, version } = parseExtensionId(id);
  if (!version) {
    console.error("error: unpin needs an exact version, e.g. unpin publisher.name@1.2.3");
    process.exit(2);
  }
  const key = `${publisher}.${name}@${version}`;
  const ok = delPin(key);
  console.log(ok ? `unpinned ${key}` : `no pin for ${key}`);
}

async function main(): Promise<void> {
  const [cmd, id, ...rest] = process.argv.slice(2);
  if (!cmd || !id) usage();
  const asJson = rest.includes("--json");
  try {
    if (cmd === "verify") await cmdVerify(id, asJson);
    else if (cmd === "pin") await cmdPin(id);
    else if (cmd === "unpin") await cmdUnpin(id);
    else usage();
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    process.exit(2);
  }
}

void main();

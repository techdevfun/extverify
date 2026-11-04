/**
 * Core verify pipeline, fetch-injectable for tests and incident replays.
 */
import {
  downloadVsix,
  fetchExtension,
  parseExtensionId,
  vsixDownloadUrl,
  type MarketplaceExtension,
} from "./market.js";
import { fetchOvsxExtension, hashRemoteVsix } from "./openvsx.js";
import { getPin } from "./pin.js";
import {
  decide,
  detectSquat,
  publisherAgeDays,
  runRules,
  type Finding,
  type RuleContext,
  type Verdict,
} from "./rules.js";
import { findBundledBinaries, readPackageJson } from "./zip.js";

export const RULES_VERSION = "2026.11";

export interface VerifyReport {
  verdict: Verdict;
  extension: {
    id: string;
    version: string;
    displayName: string;
    publisher: string;
    publisherVerified: boolean | null;
    installs: number;
    sha256: string;
  };
  findings: Finding[];
  manifest: {
    rulesVersion: string;
    checkedAt: string;
    signals: string[];
  };
}

export async function verifyExtension(
  id: string,
  fetchImpl: typeof fetch = fetch,
): Promise<VerifyReport> {
  const { publisher, name, version } = parseExtensionId(id);
  const ext: MarketplaceExtension = await fetchExtension(publisher, name, fetchImpl);
  const ver = version ?? ext.versions[0]?.version;
  if (!ver) throw new Error("marketplace returned no versions");
  if (version && !ext.versions.some((v) => v.version === ver))
    throw new Error(`version ${version} not found on marketplace`);

  const age = publisherAgeDays(ext);
  const installs = ext.statistics["install"] ?? 0;
  const velocity = age !== null && age > 0 ? installs / age : null;

  const url = vsixDownloadUrl(publisher, name, ver);
  const vsix = await downloadVsix(url, fetchImpl);
  const sha256 = vsix.sha256;
  let manifest: Record<string, unknown> | null = null;
  let binaries: string[] = [];
  let manifestSkipped = false;
  if (vsix.head) {
    try {
      manifest = readPackageJson(vsix.head);
      binaries = findBundledBinaries(vsix.head);
    } catch {
      manifest = null;
    }
  } else {
    manifestSkipped = true;
  }

  const pinKey = `${publisher}.${name}@${ver}`;

  let crossRegistry: "match" | "mismatch" | "unavailable" = "unavailable";
  try {
    const ovsx = await fetchOvsxExtension(publisher, name, fetchImpl);
    const ov = ovsx?.versions.find((v) => v.version === ver);
    if (ov) {
      const ovsxHash = await hashRemoteVsix(ov.downloadUrl, fetchImpl);
      crossRegistry = ovsxHash === sha256 ? "match" : "mismatch";
    }
  } catch {
    crossRegistry = "unavailable";
  }

  const ctx: RuleContext = {
    ext,
    publisherAgeDays: age,
    velocityPerDay: velocity,
    manifest,
    bundledBinaries: binaries,
    pinnedSha256: getPin(pinKey),
    actualSha256: sha256,
    squatTarget: detectSquat(publisher),
    manifestSkipped,
    crossRegistry,
  };
  const findings = runRules(ctx);
  const verdict = decide(findings);

  return {
    verdict,
    extension: {
      id: `${publisher}.${name}`,
      version: ver,
      displayName: ext.displayName,
      publisher: ext.publisher.publisherName,
      publisherVerified: ext.publisher.isVerified ?? null,
      installs,
      sha256,
    },
    findings,
    manifest: {
      rulesVersion: RULES_VERSION,
      checkedAt: new Date().toISOString(),
      signals: [
        "marketplace-public-api",
        ...(vsix.head ? ["vsix-manifest"] : ["vsix-manifest-skipped"]),
        ...(crossRegistry === "match" ? ["cross-registry-hash-match"] : []),
      ],
    },
  };
}

export function formatHuman(r: VerifyReport): string {
  const lines = [`${r.verdict}  ${r.extension.id}@${r.extension.version}`];
  for (const f of r.findings) lines.push(`  [${f.severity}] ${f.rule}: ${f.evidence}`);
  if (r.findings.length === 0) lines.push("  no findings");
  return lines.join("\n");
}

/**
 * Detection rules. Each rule returns findings with exact evidence strings.
 * Severity: "high" -> DENY, anything else -> REVIEW, no findings -> ALLOW.
 */
import type { MarketplaceExtension } from "./market.js";

export interface Finding {
  rule: string;
  severity: "high" | "medium" | "low";
  evidence: string;
}

export interface RuleContext {
  ext: MarketplaceExtension;
  /** days since the publisher's first published version */
  publisherAgeDays: number | null;
  /** downloads per day of publisher age */
  velocityPerDay: number | null;
  manifest: Record<string, unknown> | null;
  bundledBinaries: string[];
  pinnedSha256: string | null;
  actualSha256: string | null;
  squatTarget: string | null;
  /** true when the VSIX exceeded the inspect cap and manifest rules were skipped */
  manifestSkipped: boolean;
  /** cross-registry comparison result vs Open VSX */
  crossRegistry: "match" | "mismatch" | "unavailable";
}

/** Well-known publishers whose names are worth squatting. Source: marketplace presence, 2026-11-04. */
export const KNOWN_PUBLISHERS = [
  "ms-python",
  "ms-vscode",
  "ms-azuretools",
  "ms-kubernetes-tools",
  "github",
  "anthropic",
  "openai",
  "google",
  "redhat",
  "ms-dotnettools",
  "dbaeumer",
  "esbenp",
  "eamodio",
];

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return d[m][n];
}

/** Name-squatting: publisher name within edit distance 2 of a known publisher, but not equal. */
export function detectSquat(publisherName: string): string | null {
  const p = publisherName.toLowerCase();
  for (const known of KNOWN_PUBLISHERS) {
    if (p === known) return null;
    if (levenshtein(p, known) <= 2 && p.length >= 4) return known;
  }
  return null;
}

export function publisherAgeDays(ext: MarketplaceExtension, nowMs = Date.now()): number | null {
  if (!ext.publishedDate) return null;
  const t = Date.parse(ext.publishedDate);
  if (Number.isNaN(t)) return null;
  return Math.max(0, (nowMs - t) / 86_400_000);
}

export function runRules(ctx: RuleContext): Finding[] {
  const out: Finding[] = [];
  const { ext } = ctx;

  // --- identity rules ---
  if (ctx.squatTarget) {
    out.push({
      rule: "publisher-name-squat",
      severity: "high",
      evidence: `publisher "${ext.publisher.publisherName}" within edit distance 2 of known publisher "${ctx.squatTarget}"`,
    });
  }
  if (ctx.publisherAgeDays !== null && ctx.publisherAgeDays < 30) {
    out.push({
      rule: "publisher-too-new",
      severity: "medium",
      evidence: `publisher first published ${ctx.publisherAgeDays.toFixed(1)} days ago (< 30d)`,
    });
  }
  if (ext.publisher.isVerified === false) {
    out.push({
      rule: "publisher-unverified",
      severity: "low",
      evidence: `publisher "${ext.publisher.publisherName}" has no verified domain badge`,
    });
  }

  // --- marketplace anomaly rules ---
  // Velocity is only meaningful for YOUNG publishers: a new publisher with
  // explosive installs is the 29/10 fake-extension shape. Old publishers with
  // high sustained installs (e.g. prettier) are normal.
  if (
    ctx.publisherAgeDays !== null &&
    ctx.publisherAgeDays < 90 &&
    ctx.velocityPerDay !== null &&
    ctx.velocityPerDay > 500
  ) {
    out.push({
      rule: "download-velocity-anomaly",
      severity: "high",
      evidence: `${ctx.velocityPerDay.toFixed(0)} installs/day over ${ctx.publisherAgeDays?.toFixed(1)}d publisher age (> 500/d with age < 90d)`,
    });
  }
  const installs = ext.statistics["install"] ?? 0;
  const ratings = ext.statistics["ratingcount"] ?? 0;
  if (installs > 1000 && ratings === 0) {
    out.push({
      rule: "installs-no-ratings",
      severity: "medium",
      evidence: `${installs} installs with 0 ratings (organic extensions accumulate ratings)`,
    });
  }

  // --- manifest risk rules ---
  const m = ctx.manifest;
  if (m) {
    const activationEvents = (m.activationEvents as string[]) ?? [];
    if (activationEvents.includes("*") || activationEvents.includes("onStartupFinished")) {
      out.push({
        rule: "runs-on-startup",
        severity: "medium",
        evidence: `activationEvents includes "${activationEvents.includes("*") ? "*" : "onStartupFinished"}" (code runs at every startup)`,
      });
    }
    const contributes = (m.contributes as Record<string, unknown>) ?? {};
    const commands = (contributes.commands as unknown[]) ?? [];
    if (commands.length > 50) {
      out.push({
        rule: "excessive-commands",
        severity: "low",
        evidence: `${commands.length} contributed commands (> 50)`,
      });
    }
  }
  if (ctx.bundledBinaries.length > 0) {
    out.push({
      rule: "bundled-binary",
      severity: "medium",
      evidence: `vsix ships executable: ${ctx.bundledBinaries.slice(0, 3).join(", ")}${ctx.bundledBinaries.length > 3 ? ` (+${ctx.bundledBinaries.length - 3} more)` : ""}`,
    });
  }

  // --- pin rule ---
  if (ctx.pinnedSha256 && ctx.actualSha256 && ctx.pinnedSha256 !== ctx.actualSha256) {
    out.push({
      rule: "version-repackaged",
      severity: "high",
      evidence: `sha256 of version ${ext.versions[0]?.version} differs from pinned value (same version, different bytes)`,
    });
  }

  // --- manifest coverage ---
  if (ctx.manifestSkipped) {
    out.push({
      rule: "vsix-too-large",
      severity: "low",
      evidence: `vsix exceeds 16MB inspect cap: manifest rules skipped, identity/anomaly rules still applied`,
    });
  }

  // --- cross-registry (the 29/10 shape: right id, wrong bytes, one registry only) ---
  // A mismatch is REVIEW, not DENY: publishers legitimately repackage between
  // registries, so differing bytes warrant investigation, not an auto-block.
  // The 29/10 malicious versions were absent from both public registries entirely.
  if (ctx.crossRegistry === "mismatch") {
    out.push({
      rule: "cross-registry-hash-mismatch",
      severity: "medium",
      evidence: `version ${ext.versions[0]?.version} has different sha256 on VS Marketplace vs Open VSX — registries disagree, verify out-of-band before installing`,
    });
  } else if (ctx.crossRegistry === "unavailable") {
    out.push({
      rule: "single-registry",
      severity: "low",
      evidence: `version not found on Open VSX: cross-registry hash comparison unavailable`,
    });
  }
  return out;
}

export type Verdict = "ALLOW" | "DENY" | "REVIEW";

export function decide(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "high")) return "DENY";
  if (findings.length > 0) return "REVIEW";
  return "ALLOW";
}

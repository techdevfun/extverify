/**
 * Open VSX registry client (https://open-vsx.org/api) — public, no key.
 * Used for cross-registry hash comparison: the 29/10/2026 incident served
 * tampered bytes ONLY on one distribution path while other registries held
 * the clean artifact. Same version + different bytes across registries = DENY.
 */
import { createHash } from "node:crypto";

const API = "https://open-vsx.org/api";

export interface OvsxVersion {
  version: string;
  downloadUrl: string;
}

export async function fetchOvsxExtension(
  namespace: string,
  name: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ verified: boolean; downloadCount: number; versions: OvsxVersion[] } | null> {
  const res = await fetchImpl(`${API}/${namespace}/${name}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`open-vsx query failed: HTTP ${res.status}`);
  const d = (await res.json()) as {
    verified?: boolean;
    downloadCount?: number;
    allVersions?: Record<string, string>;
  };
  const versions: OvsxVersion[] = [];
  for (const [ver, metaUrl] of Object.entries(d.allVersions ?? {})) {
    if (ver === "latest") continue;
    try {
      const vr = await fetchImpl(String(metaUrl));
      if (!vr.ok) continue;
      const vd = (await vr.json()) as { files?: { download?: string } };
      const dl = vd?.files?.download;
      if (dl) versions.push({ version: ver, downloadUrl: String(dl) });
    } catch {
      // one bad version record must not kill the whole check
    }
  }
  return {
    verified: d.verified === true,
    downloadCount: d.downloadCount ?? 0,
    versions,
  };
}

/** Stream-download a VSIX and return its sha256 without storing the file. */
export async function hashRemoteVsix(
  url: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const res = await fetchImpl(url);
  if (!res.ok || !res.body) throw new Error(`vsix download failed: HTTP ${res.status}`);
  const hash = createHash("sha256");
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    hash.update(Buffer.from(value));
  }
  return hash.digest("hex");
}

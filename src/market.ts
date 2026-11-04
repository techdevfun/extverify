/**
 * Public Visual Studio Marketplace gallery API (no auth required for public data).
 * POST https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery
 * Verified against live API 2026-11-04.
 */

export interface MarketplaceExtension {
  publisher: {
    publisherName: string;
    displayName: string;
    /** "verified" when the publisher owns a verified domain */
    isVerified?: boolean;
  };
  extensionName: string;
  displayName: string;
  shortDescription: string;
  /** ISO date of first published version (publisher age proxy) */
  publishedDate?: string;
  lastUpdated?: string;
  statistics: Record<string, number>; // e.g. install, averagerating, ratingcount
  versions: Array<{
    version: string;
    lastUpdated: string;
    files: Array<{ assetType: string; source: string }>;
  }>;
}

const GALLERY_URL =
  "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=7.2-preview.1";

export function parseExtensionId(id: string): { publisher: string; name: string; version?: string } {
  // forms: "publisher.name", "publisher.name@1.2.3"
  const m = /^([a-z0-9][a-z0-9-]*)\.([a-z0-9][a-z0-9-]*)(?:@([0-9][0-9a-zA-Z.+-]*))?$/i.exec(id.trim());
  if (!m) throw new Error(`bad extension id: ${id} (want publisher.name[@version])`);
  return { publisher: m[1], name: m[2], version: m[3] };
}

export async function fetchExtension(
  publisher: string,
  name: string,
  fetchImpl: typeof fetch = fetch,
): Promise<MarketplaceExtension> {
  const body = {
    filters: [
      {
        criteria: [
          { filterType: 7, value: `${publisher}.${name}` }, // target = unique id
        ],
      },
    ],
    // IncludeVersions | IncludeFiles | IncludeCategoryAndTags | IncludeVersionProperties | IncludeStatistics
    flags: 0x1 | 0x2 | 0x4 | 0x10 | 0x100,
  };
  const res = await fetchImpl(GALLERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`marketplace query failed: HTTP ${res.status}`);
  const data = (await res.json()) as { results: Array<{ extensions: unknown[] }> };
  const raw = data?.results?.[0]?.extensions?.[0] as Record<string, unknown> | undefined;
  if (!raw) throw new Error(`extension not found: ${publisher}.${name}`);
  const stats: Record<string, number> = {};
  for (const s of (raw.statistics as Array<{ statisticName: string; value: number }>) ?? []) {
    stats[s.statisticName] = s.value;
  }
  const versions = ((raw.versions as Array<Record<string, unknown>>) ?? []).map((v) => ({
    version: String(v.version),
    lastUpdated: String(v.lastUpdated),
    files: ((v.files as Array<Record<string, string>>) ?? []).map((f) => ({
      assetType: String(f.assetType),
      source: String(f.source),
    })),
  }));
  const pub = raw.publisher as Record<string, unknown>;
  const pubFlags = String(pub.flags ?? "");
  return {
    publisher: {
      publisherName: String(pub.publisherName),
      displayName: String(pub.displayName),
      isVerified: pubFlags.includes("verified") || (pub.isDomainVerified as boolean) === true,
    },
    extensionName: String(raw.extensionName),
    displayName: String(raw.displayName ?? ""),
    shortDescription: String(raw.shortDescription ?? ""),
    publishedDate: raw.publishedDate as string | undefined,
    lastUpdated: raw.lastUpdated as string | undefined,
    statistics: stats,
    versions,
  };
}

export function vsixDownloadUrl(publisher: string, name: string, version: string): string {
  return (
    `https://${publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/` +
    `${publisher}/extension/${name}/${version}/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage`
  );
}

/** Max bytes fetched for manifest inspection. Larger VSIXes are still hash-pinned
 *  via streaming, but their manifest is not inspected (recorded as a signal). */
export const VSIX_INSPECT_CAP = 16 * 1024 * 1024;

export interface VsixResult {
  /** sha256 over the FULL file (streamed, exact for pinning) */
  sha256: string;
  /** first VSIX_INSPECT_CAP bytes for manifest inspection, or null when skipped */
  head: Buffer | null;
  truncated: boolean;
  bytes: number;
}

export async function downloadVsix(
  url: string,
  fetchImpl: typeof fetch = fetch,
): Promise<VsixResult> {
  const { createHash } = await import("node:crypto");
  const res = await fetchImpl(url);
  if (!res.ok || !res.body) throw new Error(`vsix download failed: HTTP ${res.status}`);
  const hash = createHash("sha256");
  const chunks: Buffer[] = [];
  let bytes = 0;
  let truncated = false;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    hash.update(chunk);
    bytes += chunk.length;
    if (!truncated) {
      const room = VSIX_INSPECT_CAP - chunks.reduce((a, c) => a + c.length, 0);
      if (room > 0) chunks.push(chunk.subarray(0, room));
      if (bytes > VSIX_INSPECT_CAP) truncated = true;
    }
  }
  return {
    sha256: hash.digest("hex"),
    head: truncated ? null : Buffer.concat(chunks),
    truncated,
    bytes,
  };
}

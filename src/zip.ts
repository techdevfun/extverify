/**
 * Minimal ZIP reader — zero dependencies.
 * Parses the central directory, then inflates DEFLATE entries with zlib.
 * Only what a VSIX inspection needs: list entries + read one file's bytes.
 */
import { inflateRawSync } from "node:zlib";

export interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: number; // 0 = stored, 8 = deflate
  localHeaderOffset: number;
}

export function listEntries(buf: Buffer): ZipEntry[] {
  // Find End Of Central Directory (EOCD) signature from the tail.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65558); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a zip file (EOCD not found)");
  const cdCount = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("bad central directory entry");
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const uncompressedSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localHeaderOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    entries.push({ name, compressedSize, uncompressedSize, method, localHeaderOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

export function readEntry(buf: Buffer, entry: ZipEntry): Buffer {
  const p = entry.localHeaderOffset;
  if (buf.readUInt32LE(p) !== 0x04034b50) throw new Error("bad local file header");
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const dataStart = p + 30 + nameLen + extraLen;
  const data = buf.subarray(dataStart, dataStart + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(data);
  if (entry.method === 8) return inflateRawSync(data);
  throw new Error(`unsupported compression method ${entry.method}`);
}

/** Read extension/package.json out of a VSIX buffer. Returns null when absent. */
export function readPackageJson(buf: Buffer): Record<string, unknown> | null {
  const entries = listEntries(buf);
  const hit = entries.find((e) => e.name.toLowerCase() === "extension/package.json");
  if (!hit) return null;
  return JSON.parse(readEntry(buf, hit).toString("utf8")) as Record<string, unknown>;
}

/** Names of any bundled executables / native binaries inside the VSIX. */
export function findBundledBinaries(buf: Buffer): string[] {
  const entries = listEntries(buf);
  return entries
    .map((e) => e.name)
    .filter(
      (n) =>
        /\.(exe|dll|so|dylib|node|bin|sh|bat|ps1|cmd)$/i.test(n) ||
        /(^|\/)bin\/[^/]+$/i.test(n),
    )
    .slice(0, 25);
}

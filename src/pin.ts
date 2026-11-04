/** Local pin store: ~/.config/extverify/pins.json — sha256 per extension@version. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

function pinPath(): string {
  const dir = join(homedir(), ".config", "extverify");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return join(dir, "pins.json");
}

function load(): Record<string, string> {
  const p = pinPath();
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

function save(pins: Record<string, string>): void {
  writeFileSync(pinPath(), JSON.stringify(pins, null, 2) + "\n");
}

export function getPin(key: string): string | null {
  return load()[key] ?? null;
}

export function setPin(key: string, sha256: string): void {
  const pins = load();
  pins[key] = sha256;
  save(pins);
}

export function delPin(key: string): boolean {
  const pins = load();
  if (!(key in pins)) return false;
  delete pins[key];
  save(pins);
  return true;
}

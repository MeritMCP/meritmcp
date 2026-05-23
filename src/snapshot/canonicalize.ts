// Deterministic hashing for schema snapshots: stable (key-sorted) stringify + SHA-256.
// (json-stable-stringify / JCS nuances can be swapped in later behind this one module.)
import { stringify } from "safe-stable-stringify";
import { createHash } from "node:crypto";

export function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function canonicalHash(obj: unknown): string {
  return sha256(stringify(obj) ?? "null");
}

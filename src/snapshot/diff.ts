// Diff two snapshots into a DriftSummary. Description-only changes are surfaced
// separately as rug-pull candidates and feed the security/score layers.
import { Snapshot } from "./capture.js";
import { DriftSummary } from "../types.js";

export function diff(prev: Snapshot, next: Snapshot): DriftSummary {
  const added: string[] = [];
  const removed: string[] = [];
  const schemaChanged: string[] = [];
  const descriptionOnly: string[] = [];

  for (const name of Object.keys(next.tools)) if (!prev.tools[name]) added.push(name);

  for (const name of Object.keys(prev.tools)) {
    const a = prev.tools[name];
    const b = next.tools[name];
    if (!b) {
      removed.push(name);
      continue;
    }
    if (a.hash !== b.hash) {
      if (a.shash !== b.shash) schemaChanged.push(name);
      else descriptionOnly.push(name);
    }
  }

  const changed = added.length + removed.length + schemaChanged.length + descriptionOnly.length > 0;
  return { hasSnapshot: true, changed, added, removed, schemaChanged, descriptionOnly };
}

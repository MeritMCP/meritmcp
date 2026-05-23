// shields.io endpoint badge JSON. Publish to gh-pages/Gist; the README references it via
// https://img.shields.io/endpoint?url=<raw-json-url>. Renders e.g. "Merit 87/100 · passing".
import { Report } from "../types.js";
import { bandColor } from "./score.js";

export interface ShieldsEndpoint {
  schemaVersion: 1;
  label: string;
  message: string;
  color: string;
}

export function toBadge(report: Report): ShieldsEndpoint {
  return {
    schemaVersion: 1,
    label: "Merit",
    message: `${report.score}/100 · ${report.verdict === "PASS" ? "passing" : "failing"}`,
    color: bandColor(report.score, report.verdict === "FAIL"),
  };
}

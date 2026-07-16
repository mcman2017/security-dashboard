// Helpers for rolling up severity counts across CRD reports.

import { ReportSummary } from './crds';
import { emptyCounts, fromTrivy,Severity, SeverityLabel } from './severity';

export function addSummary(
  acc: Record<SeverityLabel, number>,
  s: ReportSummary | undefined
): Record<SeverityLabel, number> {
  if (!s) return acc;
  acc.CRITICAL += s.criticalCount ?? 0;
  acc.HIGH += s.highCount ?? 0;
  acc.MEDIUM += s.mediumCount ?? 0;
  acc.LOW += s.lowCount ?? 0;
  acc.INFO += (s.unknownCount ?? 0) + (s.noneCount ?? 0);
  return acc;
}

export function rollupSummaries(reports: Array<{ jsonData?: { report?: { summary?: ReportSummary } } }> | null): Record<SeverityLabel, number> {
  const acc = emptyCounts();
  if (!reports) return acc;
  for (const r of reports) {
    addSummary(acc, r.jsonData?.report?.summary);
  }
  return acc;
}

// Convert a single Trivy severity string into our Severity enum.
export { fromTrivy as severityFromString };
export { Severity };

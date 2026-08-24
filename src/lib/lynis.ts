// Helpers shared by the Lynis host-audit pages (Host OS list, per-scan
// detail, per-node detail).
import { Finding, FindingWithScan, ScanDetailResponse } from './api';
import { emptyCounts, Severity, SeverityLabel, severityLabel } from './severity';

// The parser surfaces each node's hardening index as a synthetic INFO finding
// with this id (backend: scans/parsers/lynis.py).
export const HARDENING_INDEX_ID = 'LYNIS-HARDENING-INDEX';

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Color the hardening-index chip by score (Lynis's own rough banding).
export function indexColor(value: number): 'success' | 'warning' | 'error' | 'default' {
  if (Number.isNaN(value)) return 'default';
  if (value >= 75) return 'success';
  if (value >= 55) return 'warning';
  return 'error';
}

export interface NodeIndex {
  node: string;
  value: string; // '' when the node's report carried no hardening_index
  os?: string;
  kernel?: string;
  lynisVersion?: string;
}

/** One entry per node seen in the scan: hardening index (if parsed) + OS facts. */
export function nodesOf(findings: Finding[]): NodeIndex[] {
  const byNode = new Map<string, NodeIndex>();
  for (const f of findings) {
    if (!f.resource_name) continue;
    const cur = byNode.get(f.resource_name) ?? { node: f.resource_name, value: '' };
    if (f.scanner_id === HARDENING_INDEX_ID) {
      const ev = (f.evidence ?? {}) as Record<string, unknown>;
      cur.value = String(ev.hardening_index ?? '').trim();
      cur.os = ev.os_fullname ? String(ev.os_fullname) : undefined;
      cur.kernel = ev.kernel_version ? String(ev.kernel_version) : undefined;
      cur.lynisVersion = ev.lynis_version ? String(ev.lynis_version) : undefined;
    }
    byNode.set(f.resource_name, cur);
  }
  return Array.from(byNode.values()).sort((a, b) => a.node.localeCompare(b.node));
}

export function countBySeverity(findings: Finding[]): Record<SeverityLabel, number> {
  const acc = emptyCounts();
  for (const f of findings) {
    const label = severityLabel(f.severity_normalized as Severity);
    if (label) acc[label] += 1;
  }
  return acc;
}

export function filterBySeverity<T extends Finding>(findings: T[], sev: SeverityLabel | null): T[] {
  if (!sev) return findings;
  return findings.filter(f => severityLabel(f.severity_normalized as Severity) === sev);
}

/** Annotate a scan's findings with the scan metadata the shared table expects. */
export function withScan(scan: ScanDetailResponse, findings: Finding[]): FindingWithScan[] {
  const meta = {
    id: scan.id,
    scanner: scan.scanner,
    variant: scan.variant,
    started_at: scan.started_at,
  };
  return findings.map(f => ({ ...f, scan: meta }));
}

export const SEVERITY_FROM_LABEL: Record<SeverityLabel, Severity> = {
  CRITICAL: Severity.Critical,
  HIGH: Severity.High,
  MEDIUM: Severity.Medium,
  LOW: Severity.Low,
  INFO: Severity.Info,
  SUPPRESSED: Severity.Suppressed,
};

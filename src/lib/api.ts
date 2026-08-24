// Client for the dash-owned scan backend (security-dashboard-api).
//
// The backend runs in the `security-dashboard` namespace and is reached through
// the Kubernetes apiserver *service proxy* — no extra ingress, no CORS, and it
// authenticates as whatever identity Headlamp uses for the cluster. FastAPI
// serves its routes under `/api`, so the proxy path ends in `.../proxy/api`.
import { ApiProxy } from '@kinvolk/headlamp-plugin/lib';
import { SeverityLabel } from './severity';

const BASE =
  '/api/v1/namespaces/security-dashboard/services/security-dashboard-api:80/proxy/api';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export type SummaryCounts = Record<SeverityLabel, number>;

export interface ScanSummary {
  id: string;
  scanner: string;
  variant: string | null;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  summary_counts: SummaryCounts;
  job_name?: string;
}

export interface Finding {
  id?: number; // absent from backends older than the detail-page feature
  severity_normalized: number;
  severity_original: string;
  scanner_id: string | null;
  resource_ns: string | null;
  resource_kind: string | null;
  resource_name: string | null;
  image: string | null;
  title: string;
  description: string | null;
  control_id: string | null;
  evidence: Record<string, unknown> | null;
  ecosystem_bucket: boolean;
}

export interface FindingWithScan extends Finding {
  scan: { id: string; scanner: string; variant: string | null; started_at: string | null };
}

// GET /scans/{id} — the scan summary plus its findings (no `scan` annotation
// on each finding; callers that feed FindingWithScan consumers synthesize it
// from the summary).
export interface ScanDetailResponse extends ScanSummary {
  findings: Finding[];
}

// Another image/workload hit by the same CVE/check, listed on the detail page.
export interface FindingOccurrence {
  id: number;
  resource_ns: string | null;
  resource_kind: string | null;
  resource_name: string | null;
  image: string | null;
}

export interface FindingDetailResponse extends FindingWithScan {
  id: number;
  also_affects: FindingOccurrence[];
}

export type TrivyVariant = 'cis' | 'nsa' | 'vuln';
export type ScannerKind = 'trivy' | 'lynis';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  // ApiProxy.request proxies to the cluster apiserver using Headlamp's creds
  // and returns the parsed JSON body (throwing ApiError on non-2xx).
  return ApiProxy.request(BASE + path, {
    ...(init ?? {}),
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  }) as Promise<T>;
}

export const scansApi = {
  list: () => req<{ scans: ScanSummary[] }>('/scans'),
  launch: (scanner: ScannerKind, variant: TrivyVariant | null = null) =>
    req<ScanSummary>('/scans', {
      method: 'POST',
      body: JSON.stringify({ scanner, variant }),
    }),
  get: (id: string) => req<ScanDetailResponse>(`/scans/${encodeURIComponent(id)}`),
  raw: (id: string) =>
    req<{ scan_id: string; scanner: string; raw: string }>(
      `/scans/${encodeURIComponent(id)}/raw`
    ),
  remove: (id: string) =>
    req<{ id: string; deleted: boolean }>(`/scans/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  findingsBySeverity: (sev: SeverityLabel) =>
    req<{ severity: SeverityLabel; total: number; findings: FindingWithScan[] }>(
      `/findings/by-severity/${encodeURIComponent(sev)}`
    ),
  finding: (id: number | string) =>
    req<FindingDetailResponse>(`/findings/${encodeURIComponent(id)}`),
};

// The launchable scans, in display order.
export const SCAN_CHOICES: Array<{
  scanner: ScannerKind;
  variant: TrivyVariant | null;
  label: string;
  description: string;
}> = [
  { scanner: 'trivy', variant: 'cis', label: 'CIS', description: 'CIS Kubernetes Benchmark (k8s-cis-1.23)' },
  { scanner: 'trivy', variant: 'nsa', label: 'NSA', description: 'NSA/CISA Kubernetes hardening (k8s-nsa-1.0)' },
  { scanner: 'trivy', variant: 'vuln', label: 'Full Vulnerability', description: 'CVE scan across all cluster images' },
  { scanner: 'lynis', variant: null, label: 'Host OS (Lynis)', description: 'Lynis hardening audit on every cluster node' },
];

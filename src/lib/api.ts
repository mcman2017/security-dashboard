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

export interface FindingWithScan {
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
  scan: { id: string; scanner: string; variant: string | null; started_at: string | null };
}

export type TrivyVariant = 'cis' | 'nsa' | 'vuln';

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
  launch: (variant: TrivyVariant) =>
    req<ScanSummary>('/scans', {
      method: 'POST',
      body: JSON.stringify({ scanner: 'trivy', variant }),
    }),
  remove: (id: string) =>
    req<{ id: string; deleted: boolean }>(`/scans/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  findingsBySeverity: (sev: SeverityLabel) =>
    req<{ severity: SeverityLabel; total: number; findings: FindingWithScan[] }>(
      `/findings/by-severity/${encodeURIComponent(sev)}`
    ),
};

// The three launchable Trivy scans, in display order.
export const SCAN_CHOICES: Array<{ variant: TrivyVariant; label: string; description: string }> = [
  { variant: 'cis', label: 'CIS', description: 'CIS Kubernetes Benchmark (k8s-cis-1.23)' },
  { variant: 'nsa', label: 'NSA', description: 'NSA/CISA Kubernetes hardening (k8s-nsa-1.0)' },
  { variant: 'vuln', label: 'Full Vulnerability', description: 'CVE scan across all cluster images' },
];

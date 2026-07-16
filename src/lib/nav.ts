// Navigation helpers for the Security Scans plugin.
//
// Headlamp uses react-router v5; the destination URL must include the
// cluster prefix (e.g. /c/spark-cluster/security-scans/vulnerabilities).
// `useClusterPath` builds that prefix from the current URL automatically.

import { useLocation } from 'react-router';
import { SeverityLabel } from './severity';

export const BASE = '/security-scans';

export const SCANS_PATHS = {
  overview: BASE,
  findings: `${BASE}/findings`,
  vulnerabilities: `${BASE}/vulnerabilities`,
  configuration: `${BASE}/configuration`,
  rbac: `${BASE}/rbac`,
  compliance: `${BASE}/compliance`,
  secrets: `${BASE}/secrets`,
  hostOs: `${BASE}/host-os`,
  suppressions: `${BASE}/suppressions`,
} as const;

/** Returns the current cluster prefix, e.g. "/c/spark-cluster". */
export function useClusterPrefix(): string {
  const { pathname } = useLocation();
  const m = pathname.match(/^(\/c\/[^/]+)/);
  return m ? m[1] : '';
}

/** Build a URL that respects the cluster prefix + optional query string. */
export function useClusterUrl(): (path: string, params?: Record<string, string | undefined>) => string {
  const prefix = useClusterPrefix();
  return (path: string, params) => {
    const qs = params
      ? '?' +
        Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== null && v !== '')
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
          .join('&')
      : '';
    return `${prefix}${path}${qs.length > 1 ? qs : ''}`;
  };
}

/** Read ?severity=CRITICAL|HIGH|... from the current URL. */
export function useSeverityFilter(): SeverityLabel | null {
  const { search } = useLocation();
  const v = new URLSearchParams(search).get('severity');
  if (!v) return null;
  const upper = v.toUpperCase();
  const allowed: SeverityLabel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'SUPPRESSED'];
  return (allowed as string[]).includes(upper) ? (upper as SeverityLabel) : null;
}

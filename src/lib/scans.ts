// Per-scan rows for the new "Scans" table on the Security overview.
//
// One row per Trivy Operator CR across all ten report kinds. Each row carries
// the underlying KubeObject (.obj) so the table can call `.delete()` directly.

import {
  ClusterComplianceReport,
  ClusterConfigAuditReport,
  ClusterInfraAssessmentReport,
  ClusterRbacAssessmentReport,
  ConfigAuditReport,
  ExposedSecretReport,
  InfraAssessmentReport,
  RbacAssessmentReport,
  SbomReport,
  VulnerabilityReport,
} from './crds';
import { emptyCounts, fromTrivy, Severity, SeverityLabel, severityLabel } from './severity';
import { addSummary } from './summary';
import { isSuppressed, KUBESCAPE_TO_TRIVY_AVD } from './suppressions';

export type ScannerLabel =
  | 'Vulnerability'
  | 'Config Audit'
  | 'RBAC'
  | 'Infrastructure'
  | 'Exposed Secret'
  | 'Compliance'
  | 'SBOM';

export const SCANNER_LABELS: ScannerLabel[] = [
  'Vulnerability',
  'Config Audit',
  'RBAC',
  'Infrastructure',
  'Exposed Secret',
  'Compliance',
  'SBOM',
];

// URL slugs for the ScanDetail route. The scanner+ns(or '_')+name triple maps
// uniquely to one CR; the slug + ns disambiguates namespace- vs cluster-scoped
// variants (e.g. ConfigAuditReport vs ClusterConfigAuditReport).
const SLUG_BY_LABEL: Record<ScannerLabel, string> = {
  Vulnerability: 'vulnerability',
  'Config Audit': 'config-audit',
  RBAC: 'rbac',
  Infrastructure: 'infrastructure',
  'Exposed Secret': 'exposed-secret',
  Compliance: 'compliance',
  SBOM: 'sbom',
};

const LABEL_BY_SLUG: Record<string, ScannerLabel> = Object.fromEntries(
  (Object.entries(SLUG_BY_LABEL) as [ScannerLabel, string][]).map(([k, v]) => [v, k])
);

export function slugForScanner(label: ScannerLabel): string {
  return SLUG_BY_LABEL[label];
}

export function scannerForSlug(slug: string): ScannerLabel | null {
  return LABEL_BY_SLUG[slug] ?? null;
}

// Resolve a (slug, isClusterScoped) pair to the matching CRD class. Returns
// null if the combination is not valid (e.g. cluster-scoped Vulnerability).
export function classForScannerSlug(slug: string, isClusterScoped: boolean): any | null {
  switch (slug) {
    case 'vulnerability':
      return isClusterScoped ? null : VulnerabilityReport;
    case 'config-audit':
      return isClusterScoped ? ClusterConfigAuditReport : ConfigAuditReport;
    case 'rbac':
      return isClusterScoped ? ClusterRbacAssessmentReport : RbacAssessmentReport;
    case 'infrastructure':
      return isClusterScoped ? ClusterInfraAssessmentReport : InfraAssessmentReport;
    case 'exposed-secret':
      return isClusterScoped ? null : ExposedSecretReport;
    case 'compliance':
      return isClusterScoped ? ClusterComplianceReport : null;
    case 'sbom':
      return isClusterScoped ? null : SbomReport;
    default:
      return null;
  }
}

export interface ScanRow {
  id: string;
  scanner: ScannerLabel;
  ns: string;
  name: string;
  target: string;
  runAt: Date | null;
  counts: Record<SeverityLabel, number>;
  obj: any; // underlying KubeObject (has .delete())
}

// --- per-CR severity counts (CRITICAL..INFO via summary; SUPPRESSED via finding iteration) ---

function targetKindName(item: any): { kind: string; name: string } {
  const meta = item?.jsonData?.metadata ?? item?.metadata ?? {};
  const labels = meta.labels ?? {};
  const kind =
    labels['trivy-operator.resource.kind'] ||
    'Workload';
  const name =
    labels['trivy-operator.resource.name'] ||
    labels['trivy-operator.container.name'] ||
    meta.name ||
    '';
  return { kind, name };
}

function countSuppressedFindings(
  scanner: ScannerLabel,
  item: any
): number {
  const j = item?.jsonData ?? item ?? {};
  const report = j.report ?? {};
  const { kind, name } = targetKindName(item);

  let n = 0;
  const tryCount = (avdRaw: string | undefined) => {
    if (!avdRaw) return;
    const avd = KUBESCAPE_TO_TRIVY_AVD[avdRaw] ?? avdRaw;
    if (isSuppressed(avd, kind, name).matched) n += 1;
  };

  switch (scanner) {
    case 'Vulnerability': {
      const vulns: Array<{ vulnerabilityID?: string }> = report.vulnerabilities ?? [];
      for (const v of vulns) tryCount(v.vulnerabilityID);
      break;
    }
    case 'Config Audit':
    case 'RBAC':
    case 'Infrastructure': {
      const checks: Array<{ checkID?: string; success?: boolean }> = report.checks ?? [];
      for (const c of checks) {
        if (c.success) continue; // passing checks have no finding to suppress
        tryCount(c.checkID);
      }
      break;
    }
    case 'Exposed Secret': {
      const secrets: Array<{ ruleID?: string }> = report.secrets ?? [];
      for (const s of secrets) tryCount(s.ruleID);
      break;
    }
    case 'Compliance': {
      // ClusterComplianceReport stores per-control checks under .report.summaryReport.controlCheck
      // or .report.controls (older variants). Iterate whichever exists.
      const controlChecks: Array<{ id?: string }> = report.summaryReport?.controlCheck ?? [];
      for (const c of controlChecks) tryCount(c.id);
      const controls: Array<{ id?: string }> = report.controls ?? [];
      for (const c of controls) tryCount(c.id);
      break;
    }
    case 'SBOM':
      break;
  }
  return n;
}

function perReportCounts(scanner: ScannerLabel, item: any): Record<SeverityLabel, number> {
  // Try to derive counts from the per-finding list so we can rebucket suppressed
  // findings into SUPPRESSED (rather than double-counting them under their
  // original severity). If the finding list isn't present (it usually is for
  // Trivy Operator reports, but the .report.summary is the authoritative
  // fallback), fall back to .report.summary.
  const findings = flattenFindings(scanner, item);
  if (findings.length > 0) {
    const acc = emptyCounts();
    for (const f of findings) {
      const label = f.suppressed ? 'SUPPRESSED' : (severityLabel(f.severity) as SeverityLabel);
      acc[label] = (acc[label] ?? 0) + 1;
    }
    return acc;
  }
  // Fallback: trust the operator-computed summary, surface suppressions via
  // the same per-finding scan (will be 0 if findings absent).
  const acc = emptyCounts();
  const summary = item?.jsonData?.report?.summary;
  addSummary(acc, summary);
  acc.SUPPRESSED = countSuppressedFindings(scanner, item);
  return acc;
}

// --- per-finding flattener (used by ScanDetail to render the "click High"
// drill-down, and by perReportCounts to rebucket suppressed findings). ---

export interface Finding {
  /** Stable per-finding id for SimpleTable row keying. */
  id: string;
  /** Display id like a CVE/check id. */
  ref: string;
  severity: Severity;
  /** Whether this finding matches the suppressions allowlist. */
  suppressed: boolean;
  /** Short title or rule name. */
  title: string;
  /** Extra column (package@version, target, message snippet, etc). */
  extra: string;
  /** Optional URL (e.g. CVE link) for clickable id. */
  link?: string;
}

export function flattenFindings(scanner: ScannerLabel, item: any): Finding[] {
  const j = item?.jsonData ?? item ?? {};
  const report = j.report ?? {};
  const { kind, name } = targetKindName(item);

  const suppCheck = (refRaw: string | undefined): boolean => {
    if (!refRaw) return false;
    const avd = KUBESCAPE_TO_TRIVY_AVD[refRaw] ?? refRaw;
    return isSuppressed(avd, kind, name).matched;
  };

  const out: Finding[] = [];
  switch (scanner) {
    case 'Vulnerability': {
      const vulns: any[] = report.vulnerabilities ?? [];
      vulns.forEach((v, i) => {
        out.push({
          id: `vuln:${v.vulnerabilityID ?? '?'}:${v.resource ?? '?'}:${i}`,
          ref: v.vulnerabilityID ?? '?',
          severity: fromTrivy(v.severity),
          suppressed: suppCheck(v.vulnerabilityID),
          title: v.title ?? '',
          extra: v.resource
            ? `${v.resource}${v.installedVersion ? '@' + v.installedVersion : ''}${v.fixedVersion ? ' → ' + v.fixedVersion : ''}`
            : '',
          link: v.primaryLink,
        });
      });
      break;
    }
    case 'Config Audit':
    case 'RBAC':
    case 'Infrastructure': {
      const checks: any[] = report.checks ?? [];
      checks.forEach((c, i) => {
        if (c.success) return; // passing checks have no finding to surface
        out.push({
          id: `check:${c.checkID ?? '?'}:${i}`,
          ref: c.checkID ?? '?',
          severity: fromTrivy(c.severity),
          suppressed: suppCheck(c.checkID),
          title: c.title ?? '',
          extra: Array.isArray(c.messages) && c.messages.length > 0 ? c.messages[0] : c.category ?? '',
        });
      });
      break;
    }
    case 'Exposed Secret': {
      const secrets: any[] = report.secrets ?? [];
      secrets.forEach((s, i) => {
        out.push({
          id: `secret:${s.ruleID ?? '?'}:${i}`,
          ref: s.ruleID ?? '?',
          severity: fromTrivy(s.severity),
          suppressed: suppCheck(s.ruleID),
          title: s.title ?? '',
          extra: s.target || s.match || '',
        });
      });
      break;
    }
    case 'Compliance': {
      // Newer Trivy Operator: .report.summaryReport.controlCheck[]
      // Older: .report.controls[]
      const controls: any[] = report.summaryReport?.controlCheck ?? report.controls ?? [];
      controls.forEach((c, i) => {
        // Some compliance reports only list controls without per-control
        // severities — fall back to the report's CRD severity convention
        // (Critical for a failing control without explicit severity).
        const sev = fromTrivy(c.severity);
        out.push({
          id: `ctrl:${c.id ?? '?'}:${i}`,
          ref: c.id ?? '?',
          severity: sev,
          suppressed: suppCheck(c.id),
          title: c.name ?? '',
          extra:
            typeof c.totalFail === 'number'
              ? `${c.totalFail} fail / ${c.passTotal ?? '?'} pass`
              : '',
        });
      });
      break;
    }
    case 'SBOM':
      // SBOM doesn't surface "findings" in the severity sense.
      break;
  }
  return out;
}

// --- flatten a list of CRs into ScanRow[] ---

function toRows(scanner: ScannerLabel, items: any[] | null): ScanRow[] {
  if (!items) return [];
  const out: ScanRow[] = [];
  for (const it of items) {
    const j = it?.jsonData ?? it ?? {};
    const meta = j.metadata ?? {};
    const ns: string = meta.namespace ?? '';
    const name: string = meta.name ?? '';
    const ts: string | undefined = meta.creationTimestamp;
    const runAt = ts ? new Date(ts) : null;
    const target = ns ? `${ns}/${name}` : name;
    out.push({
      id: `${scanner}:${ns || '-'}:${name}`,
      scanner,
      ns,
      name,
      target,
      runAt,
      counts: perReportCounts(scanner, it),
      obj: it,
    });
  }
  return out;
}

// --- public hook: live-watched rows across all 10 CR kinds ---

export function useAllScans(): { rows: ScanRow[]; error: unknown } {
  const [vulns, eVuln] = VulnerabilityReport.useList();
  const [cfg, eCfg] = ConfigAuditReport.useList();
  const [clusterCfg, eClusterCfg] = ClusterConfigAuditReport.useList();
  const [rbac, eRbac] = RbacAssessmentReport.useList();
  const [clusterRbac, eClusterRbac] = ClusterRbacAssessmentReport.useList();
  const [infra, eInfra] = InfraAssessmentReport.useList();
  const [clusterInfra, eClusterInfra] = ClusterInfraAssessmentReport.useList();
  const [secrets, eSecrets] = ExposedSecretReport.useList();
  const [compliance, eCompliance] = ClusterComplianceReport.useList();
  const [sbom, eSbom] = SbomReport.useList();

  const rows: ScanRow[] = [
    ...toRows('Vulnerability', vulns as any),
    ...toRows('Config Audit', cfg as any),
    ...toRows('Config Audit', clusterCfg as any),
    ...toRows('RBAC', rbac as any),
    ...toRows('RBAC', clusterRbac as any),
    ...toRows('Infrastructure', infra as any),
    ...toRows('Infrastructure', clusterInfra as any),
    ...toRows('Exposed Secret', secrets as any),
    ...toRows('Compliance', compliance as any),
    ...toRows('SBOM', sbom as any),
  ];

  const error =
    eVuln || eCfg || eClusterCfg || eRbac || eClusterRbac || eInfra || eClusterInfra || eSecrets || eCompliance || eSbom;

  return { rows, error };
}

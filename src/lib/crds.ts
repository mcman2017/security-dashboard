// Trivy Operator CRD class factories.
// All CRDs live in group `aquasecurity.github.io`, version `v1alpha1`.

import { K8s } from '@kinvolk/headlamp-plugin/lib';

const GROUP = 'aquasecurity.github.io';
const VERSION = 'v1alpha1';

function makeNs(kind: string, plural: string, singular: string) {
  return K8s.crd.makeCustomResourceClass({
    apiInfo: [{ group: GROUP, version: VERSION }],
    kind,
    pluralName: plural,
    singularName: singular,
    isNamespaced: true,
  });
}

function makeCluster(kind: string, plural: string, singular: string) {
  return K8s.crd.makeCustomResourceClass({
    apiInfo: [{ group: GROUP, version: VERSION }],
    kind,
    pluralName: plural,
    singularName: singular,
    isNamespaced: false,
  });
}

// Namespace-scoped Trivy Operator reports
export const VulnerabilityReport = makeNs('VulnerabilityReport', 'vulnerabilityreports', 'vulnerabilityreport');
export const ConfigAuditReport = makeNs('ConfigAuditReport', 'configauditreports', 'configauditreport');
export const ExposedSecretReport = makeNs('ExposedSecretReport', 'exposedsecretreports', 'exposedsecretreport');
export const RbacAssessmentReport = makeNs('RbacAssessmentReport', 'rbacassessmentreports', 'rbacassessmentreport');
export const InfraAssessmentReport = makeNs('InfraAssessmentReport', 'infraassessmentreports', 'infraassessmentreport');
export const SbomReport = makeNs('SbomReport', 'sbomreports', 'sbomreport');

// Cluster-scoped reports
export const ClusterRbacAssessmentReport = makeCluster(
  'ClusterRbacAssessmentReport',
  'clusterrbacassessmentreports',
  'clusterrbacassessmentreport'
);
export const ClusterInfraAssessmentReport = makeCluster(
  'ClusterInfraAssessmentReport',
  'clusterinfraassessmentreports',
  'clusterinfraassessmentreport'
);
export const ClusterConfigAuditReport = makeCluster(
  'ClusterConfigAuditReport',
  'clusterconfigauditreports',
  'clusterconfigauditreport'
);
export const ClusterComplianceReport = makeCluster(
  'ClusterComplianceReport',
  'clustercompliancereports',
  'clustercompliancereport'
);

// --- Severity summary block that Trivy Operator embeds under .report.summary ---
export interface ReportSummary {
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  unknownCount?: number;
  noneCount?: number;
}

// --- Per-vulnerability finding (.report.vulnerabilities[N]) ---
export interface VulnerabilityItem {
  vulnerabilityID: string;
  resource?: string;
  installedVersion?: string;
  fixedVersion?: string;
  severity: string;
  primaryLink?: string;
  title?: string;
  description?: string;
  score?: number;
  publishedDate?: string;
  lastModifiedDate?: string;
}

// --- Config audit check (.report.checks[N]) ---
export interface ConfigCheck {
  checkID: string;
  title: string;
  description?: string;
  severity: string;
  category?: string;
  messages?: string[];
  success: boolean;
  remediation?: string;
}

// --- RBAC assessment check (.report.checks[N]) ---
export interface RbacCheck extends ConfigCheck {}

// --- Exposed secret (.report.secrets[N]) ---
export interface ExposedSecret {
  target?: string;
  ruleID?: string;
  title?: string;
  severity?: string;
  category?: string;
  match?: string;
}

// --- Compliance control (.report.summaryReport.controlCheck[N] for summary; full .report.controls[N] also exists) ---
export interface ComplianceControl {
  id: string;
  name: string;
  severity?: string;
  totalFail?: number;
  passTotal?: number;
}

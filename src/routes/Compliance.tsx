import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { useMemo } from 'react';
import { SeverityBadge } from '../components/SeverityBadge';
import { matchesSeverityFilter,SeverityFilterChip } from '../components/SeverityFilterChip';
import { ClusterComplianceReport, ComplianceControl } from '../lib/crds';
import { SCANS_PATHS, useSeverityFilter } from '../lib/nav';
import { fromTrivy } from '../lib/severity';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

interface Row {
  spec: string;
  controlID: string;
  controlName: string;
  severity: string;
  fail: number;
  pass: number;
}

function flatten(items: any[] | null): Row[] {
  if (!items) return [];
  const out: Row[] = [];
  for (const r of items) {
    const j = r.jsonData ?? r;
    const meta = j.metadata || {};
    const spec =
      meta.labels?.['trivy-operator.compliance.id'] ||
      j.spec?.compliance?.id ||
      meta.name;
    // ClusterComplianceReport puts its results under .status.summaryReport.controlCheck
    // (NOT .report — verified against the operator's CRD output).
    const controls: ComplianceControl[] =
      j.status?.summaryReport?.controlCheck ??
      j.report?.summaryReport?.controlCheck ??
      [];
    for (const c of controls) {
      out.push({
        spec,
        controlID: c.id,
        controlName: c.name,
        severity: c.severity ?? 'UNKNOWN',
        fail: c.totalFail ?? 0,
        pass: c.passTotal ?? 0,
      });
    }
  }
  return out;
}

export function Compliance() {
  const [items] = ClusterComplianceReport.useList();
  const severityFilter = useSeverityFilter();
  const rows = useMemo(
    () => flatten(items as any).filter(r => matchesSeverityFilter(r.severity, severityFilter)),
    [items, severityFilter]
  );
  return (
    <SectionBox title={<SectionHeader title={`Compliance (${rows.length})`} />}>
      <SeverityFilterChip basePath={SCANS_PATHS.compliance} />
      <SimpleTable
        data={rows}
        columns={[
          { label: 'Severity', getter: (r: Row) => <SeverityBadge severity={fromTrivy(r.severity)} /> },
          { label: 'Spec', getter: (r: Row) => r.spec },
          { label: 'Control', getter: (r: Row) => r.controlID },
          { label: 'Name', getter: (r: Row) => r.controlName },
          { label: 'Fail', getter: (r: Row) => r.fail },
          { label: 'Pass', getter: (r: Row) => r.pass },
        ]}
      />
    </SectionBox>
  );
}

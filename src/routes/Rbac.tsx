import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { useMemo } from 'react';
import { SeverityBadge } from '../components/SeverityBadge';
import { matchesSeverityFilter,SeverityFilterChip } from '../components/SeverityFilterChip';
import { ClusterRbacAssessmentReport, RbacAssessmentReport, RbacCheck } from '../lib/crds';
import { SCANS_PATHS, useSeverityFilter } from '../lib/nav';
import { fromTrivy, Severity, severityLabel } from '../lib/severity';
import { isSuppressed, KUBESCAPE_TO_TRIVY_AVD } from '../lib/suppressions';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

interface Row {
  scope: 'Role' | 'ClusterRole';
  ns: string;
  target: string;
  checkID: string;
  title: string;
  severityRaw: string;
  effective: Severity;
  suppressed: boolean;
  suppressionReason?: string;
  suppressionJustification?: string;
}

function flatten(items: any[] | null, scope: 'Role' | 'ClusterRole'): Row[] {
  if (!items) return [];
  const out: Row[] = [];
  for (const r of items) {
    const j = r.jsonData ?? r;
    const meta = j.metadata || {};
    const target = meta.name || '';
    const ns = scope === 'Role' ? meta.namespace || '' : '(cluster)';
    const checks: RbacCheck[] = j.report?.checks ?? [];
    for (const c of checks) {
      if (c.success) continue;
      const avd = KUBESCAPE_TO_TRIVY_AVD[c.checkID] || c.checkID;
      const sup = isSuppressed(avd, scope, target);
      const effective = sup.matched ? Severity.Suppressed : fromTrivy(c.severity);
      out.push({
        scope,
        ns,
        target,
        checkID: c.checkID,
        title: c.title,
        severityRaw: c.severity,
        effective,
        suppressed: sup.matched,
        suppressionReason: sup.reason,
        suppressionJustification: sup.justification,
      });
    }
  }
  return out;
}

export function Rbac() {
  const [nsItems] = RbacAssessmentReport.useList();
  const [clItems] = ClusterRbacAssessmentReport.useList();
  const severityFilter = useSeverityFilter();
  const rows = useMemo(() => {
    const all = [...flatten(nsItems as any, 'Role'), ...flatten(clItems as any, 'ClusterRole')];
    return all.filter(r => matchesSeverityFilter(severityLabel(r.effective), severityFilter));
  }, [nsItems, clItems, severityFilter]);
  return (
    <SectionBox title={<SectionHeader title={`RBAC assessment (${rows.length})`} />}>
      <SeverityFilterChip basePath={SCANS_PATHS.rbac} />
      <SimpleTable
        data={rows}
        columns={[
          { label: 'Severity', getter: (r: Row) => <SeverityBadge severity={r.effective} /> },
          { label: 'Original', getter: (r: Row) => (r.suppressed ? severityLabel(fromTrivy(r.severityRaw)) : '') },
          { label: 'Kind', getter: (r: Row) => r.scope },
          { label: 'Namespace', getter: (r: Row) => r.ns },
          { label: 'Target', getter: (r: Row) => r.target },
          { label: 'Check', getter: (r: Row) => r.checkID },
          { label: 'Title', getter: (r: Row) => r.title },
          { label: 'Reason', getter: (r: Row) => r.suppressionReason || '' },
        ]}
      />
    </SectionBox>
  );
}

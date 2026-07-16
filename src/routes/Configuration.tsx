import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { useMemo } from 'react';
import { SeverityBadge } from '../components/SeverityBadge';
import { matchesSeverityFilter,SeverityFilterChip } from '../components/SeverityFilterChip';
import { ClusterConfigAuditReport, ConfigAuditReport, ConfigCheck } from '../lib/crds';
import { SCANS_PATHS, useSeverityFilter } from '../lib/nav';
import { fromTrivy } from '../lib/severity';
import { isSuppressed } from '../lib/suppressions';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

interface Row {
  ns: string;
  target: string;
  checkID: string;
  title: string;
  severityRaw: string;
  category?: string;
  remediation?: string;
  suppressed: boolean;
  suppressionReason?: string;
}

function flatten(items: any[] | null, isCluster: boolean): Row[] {
  if (!items) return [];
  const out: Row[] = [];
  for (const r of items) {
    const j = r.jsonData ?? r;
    const meta = j.metadata || {};
    const target = meta.name || '';
    const ns = isCluster ? '(cluster)' : meta.namespace || '';
    const checks: ConfigCheck[] = j.report?.checks ?? [];
    for (const c of checks) {
      if (c.success) continue;
      const sup = isSuppressed(c.checkID, isCluster ? 'ClusterResource' : 'Resource', target);
      out.push({
        ns,
        target,
        checkID: c.checkID,
        title: c.title,
        severityRaw: c.severity,
        category: c.category,
        remediation: c.remediation,
        suppressed: sup.matched,
        suppressionReason: sup.reason,
      });
    }
  }
  return out;
}

export function Configuration() {
  const [ns] = ConfigAuditReport.useList();
  const [cl] = ClusterConfigAuditReport.useList();
  const severityFilter = useSeverityFilter();
  const rows = useMemo(() => {
    const all = [...flatten(ns as any, false), ...flatten(cl as any, true)];
    return all.filter(r => matchesSeverityFilter(r.severityRaw, severityFilter));
  }, [ns, cl, severityFilter]);
  return (
    <SectionBox title={<SectionHeader title={`Configuration audit (${rows.length})`} />}>
      <SeverityFilterChip basePath={SCANS_PATHS.configuration} />
      <SimpleTable
        data={rows}
        columns={[
          { label: 'Severity', getter: (r: Row) => <SeverityBadge severity={fromTrivy(r.severityRaw)} /> },
          { label: 'Check', getter: (r: Row) => r.checkID },
          { label: 'Namespace', getter: (r: Row) => r.ns },
          { label: 'Target', getter: (r: Row) => r.target },
          { label: 'Title', getter: (r: Row) => r.title },
          { label: 'Suppression', getter: (r: Row) => (r.suppressed ? r.suppressionReason : '') },
        ]}
      />
    </SectionBox>
  );
}

import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { useMemo } from 'react';
import { SeverityBadge } from '../components/SeverityBadge';
import { matchesSeverityFilter,SeverityFilterChip } from '../components/SeverityFilterChip';
import { ExposedSecret,ExposedSecretReport } from '../lib/crds';
import { SCANS_PATHS, useSeverityFilter } from '../lib/nav';
import { fromTrivy } from '../lib/severity';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

interface Row {
  ns: string;
  target: string;
  ruleID?: string;
  title?: string;
  severity?: string;
  category?: string;
}

function flatten(items: any[] | null): Row[] {
  if (!items) return [];
  const out: Row[] = [];
  for (const r of items) {
    const j = r.jsonData ?? r;
    const meta = j.metadata || {};
    const ns = meta.namespace || '';
    const target = meta.name || '';
    const secrets: ExposedSecret[] = j.report?.secrets ?? [];
    for (const s of secrets) {
      out.push({ ns, target, ruleID: s.ruleID, title: s.title, severity: s.severity, category: s.category });
    }
  }
  return out;
}

export function Secrets() {
  const [items] = ExposedSecretReport.useList();
  const severityFilter = useSeverityFilter();
  const rows = useMemo(() => flatten(items as any).filter(r => matchesSeverityFilter(r.severity, severityFilter)), [items, severityFilter]);
  return (
    <SectionBox title={<SectionHeader title={`Exposed secrets (${rows.length})`} />}>
      <SeverityFilterChip basePath={SCANS_PATHS.secrets} />
      <SimpleTable
        data={rows}
        columns={[
          { label: 'Severity', getter: (r: Row) => <SeverityBadge severity={fromTrivy(r.severity || '')} /> },
          { label: 'Namespace', getter: (r: Row) => r.ns },
          { label: 'Resource', getter: (r: Row) => r.target },
          { label: 'Rule', getter: (r: Row) => r.ruleID },
          { label: 'Category', getter: (r: Row) => r.category },
          { label: 'Title', getter: (r: Row) => r.title },
        ]}
      />
    </SectionBox>
  );
}

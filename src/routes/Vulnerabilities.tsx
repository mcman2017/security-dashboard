import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { FormControlLabel, Switch } from '@mui/material';
import { useMemo, useState } from 'react';
import { SeverityBadge } from '../components/SeverityBadge';
import { matchesSeverityFilter,SeverityFilterChip } from '../components/SeverityFilterChip';
import { VulnerabilityItem,VulnerabilityReport } from '../lib/crds';
import { isEcosystem } from '../lib/ecosystem';
import { SCANS_PATHS, useSeverityFilter } from '../lib/nav';
import { fromTrivy } from '../lib/severity';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

interface VRow {
  vrName: string;
  vrNs: string;
  workload: string;
  image: string;
  vulnID: string;
  severity: string;
  resource?: string;
  installed?: string;
  fixed?: string;
  title?: string;
  link?: string;
  ecosystem: boolean;
}

function flatten(items: any[] | null): VRow[] {
  if (!items) return [];
  const out: VRow[] = [];
  for (const r of items) {
    const j = r.jsonData ?? r;
    const meta = j.metadata || {};
    const labels = meta.labels || {};
    const report = j.report || {};
    const ns = meta.namespace || '';
    const workload =
      labels['trivy-operator.resource.name'] ||
      labels['trivy-operator.container.name'] ||
      meta.name;
    const artifact = report.artifact || {};
    const image = artifact.repository
      ? `${artifact.repository}:${artifact.tag || artifact.digest || 'latest'}`
      : labels['trivy-operator.container.name'] || 'unknown';
    const vulns: VulnerabilityItem[] = report.vulnerabilities ?? [];
    for (const v of vulns) {
      out.push({
        vrName: meta.name,
        vrNs: ns,
        workload,
        image,
        vulnID: v.vulnerabilityID,
        severity: v.severity,
        resource: v.resource,
        installed: v.installedVersion,
        fixed: v.fixedVersion,
        title: v.title,
        link: v.primaryLink,
        ecosystem: isEcosystem({ namespace: ns, image }),
      });
    }
  }
  return out;
}

export function Vulnerabilities() {
  const [items, error] = VulnerabilityReport.useList();
  const [hideEcosystem, setHideEcosystem] = useState(false);
  const severityFilter = useSeverityFilter();

  const rows = useMemo(() => {
    let flat = flatten(items as any);
    if (hideEcosystem) flat = flat.filter(r => !r.ecosystem);
    flat = flat.filter(r => matchesSeverityFilter(r.severity, severityFilter));
    return flat;
  }, [items, hideEcosystem, severityFilter]);

  return (
    <SectionBox
      title={
        <SectionHeader
          title={`Vulnerabilities (${rows.length})`}
          actions={[
            <FormControlLabel
              key="hide-eco"
              control={<Switch checked={hideEcosystem} onChange={e => setHideEcosystem(e.target.checked)} />}
              label="Hide ecosystem (system/vendor)"
            />,
          ]}
        />
      }
    >
      <SeverityFilterChip basePath={SCANS_PATHS.vulnerabilities} />
      {error ? <pre>{String(error)}</pre> : null}
      <SimpleTable
        data={rows}
        columns={[
          { label: 'Severity', getter: (r: VRow) => <SeverityBadge severity={fromTrivy(r.severity)} /> },
          {
            label: 'CVE',
            getter: (r: VRow) =>
              r.link ? (
                <a href={r.link} target="_blank" rel="noreferrer">
                  {r.vulnID}
                </a>
              ) : (
                r.vulnID
              ),
          },
          { label: 'Namespace', getter: (r: VRow) => r.vrNs },
          { label: 'Workload', getter: (r: VRow) => r.workload },
          { label: 'Image', getter: (r: VRow) => r.image },
          { label: 'Package', getter: (r: VRow) => r.resource },
          { label: 'Installed', getter: (r: VRow) => r.installed },
          { label: 'Fixed', getter: (r: VRow) => r.fixed || '—' },
          { label: 'Title', getter: (r: VRow) => r.title },
        ]}
      />
    </SectionBox>
  );
}

import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { Box, Stack, Typography } from '@mui/material';
import { useMemo } from 'react';
import { useHistory, useParams } from 'react-router';
import { SeverityBadge } from '../components/SeverityBadge';
import { SeverityFilterChip } from '../components/SeverityFilterChip';
import { StatCards } from '../components/StatCards';
import { useClusterUrl, useSeverityFilter } from '../lib/nav';
import {
  classForScannerSlug,
  Finding,
  flattenFindings,
  scannerForSlug,
  ScannerLabel,
} from '../lib/scans';
import { emptyCounts, Severity, SeverityLabel,severityLabel } from '../lib/severity';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

function fmtDate(s: string | undefined): string {
  if (!s) return '—';
  const d = new Date(s);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function bucketFor(f: Finding): SeverityLabel {
  return f.suppressed ? 'SUPPRESSED' : (severityLabel(f.severity) as SeverityLabel);
}

export function ScanDetail() {
  const params = useParams<{ scanner: string; ns: string; name: string }>();
  const scanner: ScannerLabel | null = scannerForSlug(params.scanner);
  const isClusterScoped = params.ns === '_';
  const ns = isClusterScoped ? '' : params.ns;
  const cls = scanner ? classForScannerSlug(params.scanner, isClusterScoped) : null;
  const severity = useSeverityFilter();
  const history = useHistory();
  const build = useClusterUrl();

  const basePath = `/security-scans/scan/${params.scanner}/${params.ns}/${params.name}`;

  // useGet exists on the K8s class — fetch a single CR by name (+ ns).
  // useList is also live-watched but for the detail page a one-shot get is fine.
  const [item, error]: [any, any] = cls
    ? cls.useGet(params.name, isClusterScoped ? undefined : ns)
    : [null, null];

  const findings = useMemo<Finding[]>(() => {
    if (!item || !scanner) return [];
    return flattenFindings(scanner, item);
  }, [item, scanner]);

  const counts = useMemo<Record<SeverityLabel, number>>(() => {
    const acc = emptyCounts();
    for (const f of findings) {
      const b = bucketFor(f);
      acc[b] = (acc[b] ?? 0) + 1;
    }
    return acc;
  }, [findings]);

  const visible = useMemo<Finding[]>(() => {
    if (!severity) return findings;
    return findings.filter(f => bucketFor(f) === severity);
  }, [findings, severity]);

  if (!scanner) {
    return (
      <SectionBox title={<SectionHeader title="Unknown scanner" />}>
        <Typography>
          No scanner found for slug <code>{params.scanner}</code>.
        </Typography>
      </SectionBox>
    );
  }

  if (!cls) {
    return (
      <SectionBox title={<SectionHeader title="Unsupported scope" />}>
        <Typography>
          The {scanner} scanner has no {isClusterScoped ? 'cluster-scoped' : 'namespaced'} variant.
        </Typography>
      </SectionBox>
    );
  }

  if (!item && !error) {
    return (
      <SectionBox title={<SectionHeader title={`Loading ${scanner} scan…`} />}>
        <Typography color="text.secondary">Fetching {params.name}…</Typography>
      </SectionBox>
    );
  }

  if (!item) {
    return (
      <SectionBox title={<SectionHeader title={`${scanner} scan not found`} />}>
        <Typography color="error">{String(error)}</Typography>
        <Typography sx={{ mt: 1 }} color="text.secondary">
          The {scanner} scan {isClusterScoped ? '' : `${ns}/`}{params.name} no longer
          exists. Trivy Operator may have rotated it out; return to{' '}
          <a
            href={build('/security-scans')}
            onClick={e => {
              e.preventDefault();
              history.push(build('/security-scans'));
            }}
          >
            Security overview
          </a>
          .
        </Typography>
      </SectionBox>
    );
  }

  const ts = item?.jsonData?.metadata?.creationTimestamp;
  const target = isClusterScoped ? params.name : `${ns}/${params.name}`;

  const goSeverity = (s: Severity) => {
    history.push(build(basePath, { severity: severityLabel(s) }));
  };
  const highlighted: Severity | undefined =
    severity === null || severity === undefined
      ? undefined
      : ({
          CRITICAL: Severity.Critical,
          HIGH: Severity.High,
          MEDIUM: Severity.Medium,
          LOW: Severity.Low,
          INFO: Severity.Info,
          SUPPRESSED: Severity.Suppressed,
        } as const)[severity];

  return (
    <SectionBox title={<SectionHeader title={`${scanner} scan: ${target}`} />}>
      <Stack spacing={2}>
        <Typography variant="body2" color="text.secondary">
          Run at: {fmtDate(ts)}
          {isClusterScoped ? null : (
            <>
              {' '}· Namespace: <code>{ns}</code>
            </>
          )}{' '}· Click a severity to filter the findings below.
        </Typography>

        <StatCards counts={counts} onSelect={goSeverity} highlighted={highlighted} />

        <SeverityFilterChip basePath={basePath} />

        <Box>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Findings ({visible.length}
            {severity ? ` of ${findings.length}` : ''})
          </Typography>
          <SimpleTable
            data={visible}
            rowsPerPage={[25, 50, 100]}
            showPagination
            columns={[
              {
                label: 'Severity',
                getter: (f: Finding) => (
                  <SeverityBadge severity={f.suppressed ? Severity.Suppressed : f.severity} />
                ),
                sort: (a: Finding, b: Finding) =>
                  (a.suppressed ? 0 : a.severity) - (b.suppressed ? 0 : b.severity),
              },
              {
                label: 'ID',
                getter: (f: Finding) =>
                  f.link ? (
                    <a href={f.link} target="_blank" rel="noreferrer">
                      {f.ref}
                    </a>
                  ) : (
                    f.ref
                  ),
                sort: (a: Finding, b: Finding) => a.ref.localeCompare(b.ref),
              },
              {
                label: 'Title',
                getter: (f: Finding) => f.title,
                sort: (a: Finding, b: Finding) => a.title.localeCompare(b.title),
              },
              {
                label: 'Detail',
                getter: (f: Finding) => f.extra,
              },
            ]}
            emptyMessage={severity ? `No ${severity.toLowerCase()} findings in this scan.` : 'No findings in this scan.'}
          />
        </Box>
      </Stack>
    </SectionBox>
  );
}

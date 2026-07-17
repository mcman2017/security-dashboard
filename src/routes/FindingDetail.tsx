// Full-page detail for one backend finding — reached by clicking a row on the
// findings-by-severity pages (`/security-scans/finding/:id`). Shows where the
// issue lives in the cluster (image / namespace / workload), the package and
// fix for CVEs (or the resolution for misconfig/compliance checks), the full
// description, external references (Trivy's AVD PrimaryURL + NVD), and every
// other image/workload hit by the same issue.
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { Alert, Box, Link as MuiLink, Paper, Stack, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { Link as RouterLink } from 'react-router-dom';
import { SeverityBadge } from '../components/SeverityBadge';
import { FindingDetailResponse, FindingOccurrence, scansApi } from '../lib/api';
import { SCANS_PATHS, useClusterUrl } from '../lib/nav';
import { Severity, severityLabel } from '../lib/severity';

const { NameValueTable, SectionBox, SectionHeader, SimpleTable } = CommonComponents;

// Shape of Finding.evidence as written by the backend Trivy parser
// (backend/src/sec_dashboard/scans/parsers/trivy.py). Vulns and
// misconfig/compliance findings populate different subsets.
interface Evidence {
  pkg?: string;
  installed?: string;
  fixed?: string;
  cvss?: Record<string, { V2Score?: number; V3Score?: number; V2Vector?: string; V3Vector?: string }>;
  primary_url?: string;
  references?: string[];
  target?: string;
  type?: string;
  message?: string;
  resolution?: string;
  compliance?: string;
  control_severity?: string;
  check_result?: string;
  avd_id?: string;
  rule_id?: string;
  match?: string;
}

function fmtDate(s: string | null | undefined): string {
  if (!s) return '—';
  const d = new Date(s);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function occurrenceResource(o: FindingOccurrence): string {
  return [o.resource_ns, o.resource_kind, o.resource_name].filter(Boolean).join('/') || '—';
}

export function FindingDetail() {
  const { id } = useParams<{ id: string }>();
  const build = useClusterUrl();

  const [finding, setFinding] = useState<FindingDetailResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    setFinding(null);
    scansApi
      .finding(id)
      .then(f => {
        if (alive) setFinding(f);
      })
      .catch(e => {
        if (alive) setError(e);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [id]);

  if (loading) {
    return (
      <SectionBox title={<SectionHeader title="Loading finding…" />}>
        <Typography color="text.secondary">Fetching finding #{id}…</Typography>
      </SectionBox>
    );
  }

  if (error || !finding) {
    const status = (error as { status?: number } | null)?.status;
    return (
      <SectionBox title={<SectionHeader title="Finding not found" />}>
        <Alert severity={status === 404 ? 'info' : 'error'}>
          {status === 404
            ? `Finding #${id} no longer exists — findings are renumbered when scan results are re-imported or a scan is deleted.`
            : `Failed to load finding #${id}: ${String((error as any)?.message ?? error)}`}{' '}
          Return to the{' '}
          <MuiLink component={RouterLink} to={build(SCANS_PATHS.overview)}>
            Security overview
          </MuiLink>
          .
        </Alert>
      </SectionBox>
    );
  }

  const ev: Evidence = (finding.evidence ?? {}) as Evidence;
  const sevLabel = severityLabel(finding.severity_normalized as Severity);
  const idLabel = finding.scanner_id ?? finding.control_id ?? `#${finding.id}`;
  const isVuln = Boolean(ev.pkg || ev.installed);
  const isCve = (finding.scanner_id ?? '').toUpperCase().startsWith('CVE-');

  const workload =
    [finding.resource_kind, finding.resource_name].filter(Boolean).join('/') || null;

  const whereRows = [
    { name: 'Image', value: finding.image ? <code>{finding.image}</code> : null, hide: !finding.image },
    { name: 'Namespace', value: finding.resource_ns ? <code>{finding.resource_ns}</code> : null, hide: !finding.resource_ns },
    { name: 'Workload', value: workload ? <code>{workload}</code> : null, hide: !workload },
    {
      name: 'Scan target',
      value: ev.target ? <code>{ev.target}</code> : null,
      hide: !ev.target || ev.target === finding.image,
    },
    {
      name: 'Found by scan',
      value: `${finding.scan.scanner}${finding.scan.variant ? ` · ${finding.scan.variant}` : ''} · ${fmtDate(finding.scan.started_at)}`,
    },
    { name: 'Original severity', value: finding.severity_original || '—' },
  ];

  const cvssRows = Object.entries(ev.cvss ?? {}).map(([source, s]) => ({
    name: `CVSS (${source})`,
    value: [
      typeof s.V3Score === 'number'
        ? `${s.V3Score}`
        : typeof s.V2Score === 'number'
          ? `${s.V2Score} (v2)`
          : null,
      s.V3Vector ?? s.V2Vector ?? null,
    ]
      .filter(Boolean)
      .join(' — '),
  }));

  const recommendedFix = isVuln
    ? ev.fixed
      ? `Upgrade ${ev.pkg ?? 'the affected package'} from ${ev.installed ?? '?'} to ${ev.fixed} (rebuild or update the image "${finding.image ?? ev.target ?? ''}").`
      : 'No fixed version has been released yet. Monitor the advisory links below and consider mitigating exposure (network policy, reduced privileges) until a patched package ships.'
    : ev.resolution || null;

  const vulnRows = [
    { name: 'Package', value: ev.pkg ? <code>{ev.pkg}</code> : null, hide: !ev.pkg },
    { name: 'Installed version', value: ev.installed ? <code>{ev.installed}</code> : null, hide: !ev.installed },
    {
      name: 'Fixed version',
      value: ev.fixed ? <code>{ev.fixed}</code> : 'No fix available yet',
    },
    ...cvssRows,
  ];

  const checkRows = [
    { name: 'Check type', value: ev.type, hide: !ev.type },
    { name: 'Message', value: ev.message, hide: !ev.message },
    { name: 'Check result', value: ev.check_result, hide: !ev.check_result },
    { name: 'Compliance', value: ev.compliance, hide: !ev.compliance },
    { name: 'Control ID', value: finding.control_id ?? ev.avd_id ?? ev.rule_id, hide: !(finding.control_id ?? ev.avd_id ?? ev.rule_id) },
  ];

  const nvdUrl = isCve ? `https://nvd.nist.gov/vuln/detail/${finding.scanner_id}` : null;
  const links: Array<{ label: string; url: string }> = [];
  if (ev.primary_url) links.push({ label: 'Aqua Vulnerability Database (Trivy)', url: ev.primary_url });
  if (nvdUrl && nvdUrl !== ev.primary_url) links.push({ label: 'NVD', url: nvdUrl });
  const references = (ev.references ?? []).filter(r => r && r !== ev.primary_url && r !== nvdUrl);

  return (
    <SectionBox
      title={
        <SectionHeader
          title={idLabel}
          actions={[
            <MuiLink
              key="back"
              component={RouterLink}
              to={build(SCANS_PATHS.findings, { severity: sevLabel })}
            >
              ← {sevLabel} findings
            </MuiLink>,
          ]}
        />
      }
    >
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <SeverityBadge severity={finding.severity_normalized as Severity} />
          <Typography variant="h6">{finding.title}</Typography>
        </Box>

        <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Where in the cluster
          </Typography>
          <NameValueTable rows={whereRows} />
        </Paper>

        {isVuln ? (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Affected package
            </Typography>
            <NameValueTable rows={vulnRows} />
          </Paper>
        ) : checkRows.some(r => !r.hide) ? (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Check details
            </Typography>
            <NameValueTable rows={checkRows} />
          </Paper>
        ) : null}

        {recommendedFix ? (
          <Alert severity="success" icon={false}>
            <Typography variant="subtitle2">Recommended fix</Typography>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
              {recommendedFix}
            </Typography>
          </Alert>
        ) : null}

        {finding.description ? (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Description
            </Typography>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-line' }}>
              {finding.description}
            </Typography>
          </Paper>
        ) : null}

        {links.length > 0 || references.length > 0 ? (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              References
            </Typography>
            <Stack spacing={0.5}>
              {links.map(l => (
                <MuiLink key={l.url} href={l.url} target="_blank" rel="noreferrer">
                  {l.label}: {l.url}
                </MuiLink>
              ))}
              {references.map(r => (
                <MuiLink key={r} href={r} target="_blank" rel="noreferrer" variant="body2">
                  {r}
                </MuiLink>
              ))}
            </Stack>
          </Paper>
        ) : null}

        {finding.also_affects.length > 0 ? (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Also affects ({finding.also_affects.length} other occurrence
              {finding.also_affects.length === 1 ? '' : 's'} of {idLabel})
            </Typography>
            <SimpleTable
              data={finding.also_affects}
              rowsPerPage={[10, 25, 50]}
              showPagination
              columns={[
                {
                  label: 'Image',
                  getter: (o: FindingOccurrence) =>
                    o.image ? (
                      <MuiLink
                        component={RouterLink}
                        to={build(`/security-scans/finding/${o.id}`)}
                      >
                        {o.image}
                      </MuiLink>
                    ) : (
                      <MuiLink
                        component={RouterLink}
                        to={build(`/security-scans/finding/${o.id}`)}
                      >
                        (no image)
                      </MuiLink>
                    ),
                },
                { label: 'Resource', getter: occurrenceResource },
              ]}
              emptyMessage="No other occurrences."
            />
          </Box>
        ) : null}

        <Typography variant="caption" color="text.secondary">
          Finding #{finding.id} · links open in a new tab · use the browser back button or the
          link above to return to the {sevLabel} list.
        </Typography>
      </Stack>
    </SectionBox>
  );
}

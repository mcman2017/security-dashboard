// Per-node view of one Lynis host audit: that node's hardening index and OS
// facts, severity totals that filter the table, and its findings. Reached by
// clicking a node chip on the audit detail page.
import { Icon } from '@iconify/react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { Alert, Box, Chip, CircularProgress, Link as MuiLink, Stack, Typography } from '@mui/material';
import { useCallback, useMemo } from 'react';
import { useHistory, useParams } from 'react-router';
import { Link as RouterLink } from 'react-router-dom';
import { SeverityFilterChip } from '../components/SeverityFilterChip';
import { SortableFindingsTable } from '../components/SortableFindingsTable';
import { StatCards } from '../components/StatCards';
import { FindingWithScan, scansApi } from '../lib/api';
import {
  countBySeverity,
  filterBySeverity,
  fmtDate,
  indexColor,
  nodesOf,
  SEVERITY_FROM_LABEL,
  withScan,
} from '../lib/lynis';
import { SCANS_PATHS, useClusterUrl, useSeverityFilter } from '../lib/nav';
import { Severity, severityLabel } from '../lib/severity';
import { usePolling } from '../lib/usePolling';

const { SectionBox, SectionHeader } = CommonComponents;

export function LynisNodeDetail() {
  const params = useParams<{ id: string; node: string }>();
  const id = params.id;
  const node = decodeURIComponent(params.node);
  const history = useHistory();
  const build = useClusterUrl();
  const severity = useSeverityFilter();

  const scanPath = `${SCANS_PATHS.hostOs}/scan/${id}`;
  const basePath = `${scanPath}/node/${encodeURIComponent(node)}`;

  const fetchScan = useCallback(() => scansApi.get(id), [id]);
  const { data: scan, error, loading } = usePolling(fetchScan, 5000);

  const nodeFindings: FindingWithScan[] = useMemo(
    () =>
      scan ? withScan(scan, (scan.findings ?? []).filter(f => f.resource_name === node)) : [],
    [scan, node]
  );
  const info = useMemo(() => nodesOf(nodeFindings)[0], [nodeFindings]);
  const counts = useMemo(() => countBySeverity(nodeFindings), [nodeFindings]);
  const visible = useMemo(() => filterBySeverity(nodeFindings, severity), [nodeFindings, severity]);

  const goSeverity = (s: Severity) => {
    history.push(build(basePath, { severity: severityLabel(s) }));
  };
  const highlighted = severity ? SEVERITY_FROM_LABEL[severity] : undefined;

  const facts = [
    info?.os ? `OS: ${info.os}` : null,
    info?.kernel ? `kernel: ${info.kernel}` : null,
    info?.lynisVersion ? `Lynis ${info.lynisVersion}` : null,
  ].filter(Boolean) as string[];

  return (
    <SectionBox
      title={
        <SectionHeader
          title={`Lynis host audit — ${node} — ${fmtDate(scan?.started_at ?? null)}`}
          subtitle={scan ? `status: ${scan.status}` : ''}
          actions={[
            <MuiLink key="scan" component={RouterLink} to={build(scanPath)}>
              ← Audit detail
            </MuiLink>,
            <MuiLink key="host" component={RouterLink} to={build(SCANS_PATHS.hostOs)} sx={{ ml: 2 }}>
              ← Host OS
            </MuiLink>,
          ]}
        />
      }
    >
      <Stack spacing={3}>
        {error ? (
          <Alert severity="error">
            Could not load scan {id}: {String((error as any)?.message ?? error)}
          </Alert>
        ) : null}
        {loading && !scan ? <CircularProgress size={24} /> : null}
        {scan && scan.status === 'completed' && nodeFindings.length === 0 ? (
          <Alert severity="warning">
            This audit has no findings for node <code>{node}</code> — it may not have been part of
            the run, or its Job failed before reporting.
          </Alert>
        ) : null}

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Chip
            color={indexColor(Number(info?.value || NaN))}
            variant="outlined"
            icon={<Icon icon="mdi:server" width={16} height={16} />}
            label={`Hardening index: ${info?.value || '?'} / 100`}
          />
          {facts.length ? (
            <Typography variant="body2" color="text.secondary">
              {facts.join(' · ')}
            </Typography>
          ) : null}
        </Box>

        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Severity totals on {node} — click a card to filter the findings below
          </Typography>
          <StatCards counts={counts} onSelect={goSeverity} highlighted={highlighted} />
        </Box>

        <Box>
          <SeverityFilterChip basePath={basePath} />
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Findings ({visible.length}
            {severity ? ` of ${nodeFindings.length}` : ''})
          </Typography>
          <SortableFindingsTable
            findings={visible}
            columns={['severity', 'id', 'title', 'original']}
            emptyMessage={
              severity
                ? `No ${severity} findings on ${node} in this audit.`
                : loading && !scan
                  ? 'Loading findings…'
                  : `No findings on ${node} in this audit.`
            }
            onRowClick={f => {
              if (f.id !== undefined) history.push(build(`/security-scans/finding/${f.id}`));
            }}
          />
        </Box>
      </Stack>
    </SectionBox>
  );
}

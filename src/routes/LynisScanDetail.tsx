// Per-scan detail for a Lynis host audit: per-node hardening indexes (click a
// node to see just its findings), severity totals that filter the table, the
// parsed findings across every node, and the raw report.dat bundle.
// Reached from the Host OS page's scan list or its severity cards.
import { Icon } from '@iconify/react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Chip,
  CircularProgress,
  Link as MuiLink,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { useCallback, useMemo, useState } from 'react';
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

export function LynisScanDetail() {
  const { id } = useParams<{ id: string }>();
  const history = useHistory();
  const build = useClusterUrl();
  const severity = useSeverityFilter();

  const basePath = `${SCANS_PATHS.hostOs}/scan/${id}`;

  const fetchScan = useCallback(() => scansApi.get(id), [id]);
  const { data: scan, error, loading } = usePolling(fetchScan, 5000);

  const [raw, setRaw] = useState<string | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);
  const [rawLoading, setRawLoading] = useState(false);

  async function loadRaw(expanded: boolean) {
    if (!expanded || raw !== null || rawLoading) return;
    setRawLoading(true);
    setRawError(null);
    try {
      const res = await scansApi.raw(id);
      setRaw(res.raw || '(empty)');
    } catch (e: any) {
      setRawError(e?.message ? String(e.message) : 'failed to load raw output');
    } finally {
      setRawLoading(false);
    }
  }

  // Every finding, hardening-index rows included, so the severity totals here
  // line up with the Host OS page's counts (the index rows are INFO).
  const all: FindingWithScan[] = useMemo(
    () => (scan ? withScan(scan, scan.findings ?? []) : []),
    [scan]
  );
  const nodes = useMemo(() => nodesOf(all), [all]);
  const counts = useMemo(() => countBySeverity(all), [all]);
  const visible = useMemo(() => filterBySeverity(all, severity), [all, severity]);

  const goSeverity = (s: Severity) => {
    history.push(build(basePath, { severity: severityLabel(s) }));
  };
  const highlighted = severity ? SEVERITY_FROM_LABEL[severity] : undefined;

  return (
    <SectionBox
      title={
        <SectionHeader
          title={`Lynis host audit — ${fmtDate(scan?.started_at ?? null)}`}
          subtitle={scan ? `status: ${scan.status}` : ''}
          actions={[
            <MuiLink key="back" component={RouterLink} to={build(SCANS_PATHS.hostOs)}>
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
        {scan && (scan.status === 'running' || scan.status === 'pending') ? (
          <Alert severity="info">
            Audit in progress — one Job per node; results appear when every node finishes.
            This page refreshes automatically.
          </Alert>
        ) : null}
        {scan?.error ? (
          <Alert severity={scan.status === 'failed' ? 'error' : 'warning'}>
            <Box component="pre" sx={{ m: 0, whiteSpace: 'pre-wrap', fontSize: 12 }}>
              {scan.error}
            </Box>
          </Alert>
        ) : null}

        {nodes.length > 0 ? (
          <Box>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>
              Hardening index by node (0–100, higher is better) — click a node for its findings
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {nodes.map(h => (
                <Tooltip key={h.node} title={`All findings on ${h.node}`}>
                  <Chip
                    color={indexColor(Number(h.value || NaN))}
                    variant="outlined"
                    clickable
                    icon={<Icon icon="mdi:server" width={16} height={16} />}
                    label={`${h.node}: ${h.value || '?'}`}
                    onClick={() =>
                      history.push(build(`${basePath}/node/${encodeURIComponent(h.node)}`))
                    }
                  />
                </Tooltip>
              ))}
            </Box>
          </Box>
        ) : null}

        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Severity totals — click a card to filter the findings below
          </Typography>
          <StatCards counts={counts} onSelect={goSeverity} highlighted={highlighted} />
        </Box>

        <Box>
          <SeverityFilterChip basePath={basePath} />
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Findings ({visible.length}
            {severity ? ` of ${all.length}` : ''})
          </Typography>
          <SortableFindingsTable
            findings={visible}
            columns={['severity', 'id', 'title', 'node', 'original']}
            emptyMessage={
              severity
                ? `No ${severity} findings in this audit.`
                : scan?.status === 'completed'
                  ? 'No findings — every node came back clean.'
                  : 'No findings yet.'
            }
            onRowClick={f => {
              if (f.id !== undefined) history.push(build(`/security-scans/finding/${f.id}`));
            }}
          />
        </Box>

        <Accordion onChange={(_e, expanded) => loadRaw(expanded)}>
          <AccordionSummary expandIcon={<Icon icon="mdi:chevron-down" width={20} height={20} />}>
            <Typography>Raw report.dat (all nodes)</Typography>
          </AccordionSummary>
          <AccordionDetails>
            {rawLoading ? <CircularProgress size={20} /> : null}
            {rawError ? <Alert severity="error">{rawError}</Alert> : null}
            {raw !== null ? (
              <Box
                component="pre"
                sx={{
                  backgroundColor: '#1e1e1e',
                  color: '#d4d4d4',
                  p: 2,
                  borderRadius: 1,
                  maxHeight: '70vh',
                  overflow: 'auto',
                  fontSize: 12,
                  lineHeight: 1.4,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {raw}
              </Box>
            ) : null}
          </AccordionDetails>
        </Accordion>
      </Stack>
    </SectionBox>
  );
}

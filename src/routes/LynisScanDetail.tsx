// Per-scan detail for a Lynis host audit: per-node hardening indexes, the
// parsed findings across every node, and the raw report.dat bundle.
// Reached from the Host OS page's scan list.
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
  Stack,
  Typography,
} from '@mui/material';
import { useCallback, useMemo, useState } from 'react';
import { useHistory, useParams } from 'react-router';
import { SortableFindingsTable } from '../components/SortableFindingsTable';
import { Finding, FindingWithScan, scansApi } from '../lib/api';
import { useClusterUrl } from '../lib/nav';
import { usePolling } from '../lib/usePolling';

const { SectionBox, SectionHeader } = CommonComponents;

const HARDENING_INDEX_ID = 'LYNIS-HARDENING-INDEX';

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Color the hardening-index chip by score (Lynis's own rough banding).
function indexColor(value: number): 'success' | 'warning' | 'error' | 'default' {
  if (Number.isNaN(value)) return 'default';
  if (value >= 75) return 'success';
  if (value >= 55) return 'warning';
  return 'error';
}

export function LynisScanDetail() {
  const { id } = useParams<{ id: string }>();
  const history = useHistory();
  const build = useClusterUrl();

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

  const findings: Finding[] = scan?.findings ?? [];

  // Per-node hardening indexes come from the parser's synthetic INFO findings.
  const hardeningByNode = useMemo(() => {
    const out: Array<{ node: string; value: string }> = [];
    for (const f of findings) {
      if (f.scanner_id === HARDENING_INDEX_ID && f.resource_name) {
        const value = String((f.evidence as any)?.hardening_index ?? '').trim();
        out.push({ node: f.resource_name, value });
      }
    }
    return out.sort((a, b) => a.node.localeCompare(b.node));
  }, [findings]);

  // Table shows the actionable warnings/suggestions; the index rows are
  // already surfaced as chips above.
  const tableFindings: FindingWithScan[] = useMemo(() => {
    if (!scan) return [];
    const meta = {
      id: scan.id,
      scanner: scan.scanner,
      variant: scan.variant,
      started_at: scan.started_at,
    };
    return findings
      .filter(f => f.scanner_id !== HARDENING_INDEX_ID)
      .map(f => ({ ...f, scan: meta }));
  }, [scan, findings]);

  return (
    <SectionBox
      title={
        <SectionHeader
          title={`Lynis host audit — ${fmtDate(scan?.started_at ?? null)}`}
          subtitle={scan ? `status: ${scan.status}` : ''}
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

        {hardeningByNode.length > 0 ? (
          <Box>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>
              Hardening index by node (0–100, higher is better)
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {hardeningByNode.map(h => (
                <Chip
                  key={h.node}
                  color={indexColor(Number(h.value))}
                  variant="outlined"
                  icon={<Icon icon="mdi:server" width={16} height={16} />}
                  label={`${h.node}: ${h.value || '?'}`}
                />
              ))}
            </Box>
          </Box>
        ) : null}

        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Findings ({tableFindings.length})
          </Typography>
          <SortableFindingsTable
            findings={tableFindings}
            emptyMessage={
              scan?.status === 'completed'
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

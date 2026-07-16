// Security Scans → Overview. The data comes from the companion backend
// (security-dashboard-api) which runs Trivy scans on THIS cluster on demand:
//   1. Rolled-up severity totals across completed scans (click a card → drill
//      into exactly those findings).
//   2. Launch a scan — CIS / NSA / Full Vulnerability.
//   3. All Scans — the launched runs, each deletable (frees storage + updates
//      the totals above).
import { Icon } from '@iconify/react';
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { ReactNode, useMemo, useState } from 'react';
import { useHistory } from 'react-router';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatCards } from '../components/StatCards';
import { SCAN_CHOICES, scansApi, ScanSummary, SummaryCounts, TrivyVariant } from '../lib/api';
import { SCANS_PATHS, useClusterUrl } from '../lib/nav';
import { emptyCounts, Severity, SEVERITY_ORDER, severityLabel } from '../lib/severity';
import { usePolling } from '../lib/usePolling';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

const VARIANT_LABEL: Record<string, string> = { cis: 'CIS', nsa: 'NSA', vuln: 'Full Vulnerability' };

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function rollUp(scans: ScanSummary[]): SummaryCounts {
  const out = emptyCounts();
  for (const s of scans) {
    if (s.status !== 'completed') continue;
    for (const label of SEVERITY_ORDER.map(severityLabel)) {
      out[label] += s.summary_counts?.[label] ?? 0;
    }
  }
  return out;
}

function statusChip(status: ScanSummary['status']): ReactNode {
  const color =
    status === 'completed'
      ? 'success'
      : status === 'failed'
        ? 'error'
        : status === 'running'
          ? 'warning'
          : 'default';
  return <Chip label={status} color={color as any} size="small" variant="outlined" />;
}

export function Overview() {
  const history = useHistory();
  const build = useClusterUrl();
  const { data, error, loading, refetch } = usePolling(scansApi.list, 5000);

  const [launching, setLaunching] = useState<TrivyVariant | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [toDelete, setToDelete] = useState<ScanSummary | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const scans = data?.scans ?? [];
  const totals = useMemo(() => rollUp(scans), [scans]);
  const anyRunning = scans.some(s => s.status === 'running' || s.status === 'pending');

  const goSeverity = (s: Severity) => {
    history.push(build(SCANS_PATHS.findings, { severity: severityLabel(s) }));
  };

  async function launch(variant: TrivyVariant) {
    setLaunching(variant);
    setLaunchError(null);
    try {
      await scansApi.launch(variant);
      await refetch();
    } catch (e: any) {
      setLaunchError(e?.message ? String(e.message) : 'launch failed');
    } finally {
      setLaunching(null);
    }
  }

  async function confirmDelete() {
    if (!toDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await scansApi.remove(toDelete.id);
      setToDelete(null);
      await refetch();
    } catch (e: any) {
      setDeleteError(e?.message ? String(e.message) : 'delete failed');
    } finally {
      setDeleting(false);
    }
  }

  const countsCell = (s: ScanSummary): ReactNode => {
    const badges = SEVERITY_ORDER.filter(sev => (s.summary_counts?.[severityLabel(sev)] ?? 0) > 0).map(
      sev => (
        <SeverityBadge key={sev} severity={sev} count={s.summary_counts[severityLabel(sev)]} />
      )
    );
    return badges.length ? (
      <Box sx={{ display: 'inline-flex', flexWrap: 'wrap', gap: 0.5 }}>{badges}</Box>
    ) : (
      <Typography variant="caption" color="text.secondary">
        {s.status === 'completed' ? 'No findings' : '—'}
      </Typography>
    );
  };

  return (
    <SectionBox title={<SectionHeader title="Security overview" />}>
      <Stack spacing={4}>
        {error ? (
          <Alert severity="error">
            Could not reach the scan backend (security-dashboard-api). If it is not installed
            yet, deploy it with the project's Helm chart into the <code>security-dashboard</code>{' '}
            namespace (see the install docs). If it is installed, the Headlamp identity may be
            missing <code>services/proxy</code> access in that namespace. Details:{' '}
            {String((error as any)?.message ?? error)}
          </Alert>
        ) : null}

        {/* 1. Rolled-up severity across completed scans */}
        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Rolled-up severity (completed scans — click a card to see those findings)
          </Typography>
          <StatCards counts={totals} onSelect={goSeverity} />
        </Box>

        {/* 2. Launch a scan */}
        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Launch a Trivy scan on this cluster
          </Typography>
          {launchError ? (
            <Alert severity="error" sx={{ mb: 1 }}>
              {launchError}
            </Alert>
          ) : null}
          <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
            {SCAN_CHOICES.map(c => (
              <Tooltip key={c.variant} title={c.description}>
                <span>
                  <Button
                    variant="contained"
                    disabled={launching !== null}
                    startIcon={
                      launching === c.variant ? (
                        <CircularProgress size={16} color="inherit" />
                      ) : (
                        <Icon icon="mdi:shield-search" width={18} height={18} />
                      )
                    }
                    onClick={() => launch(c.variant)}
                  >
                    {c.label}
                  </Button>
                </span>
              </Tooltip>
            ))}
            {anyRunning ? (
              <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
                a scan is running — this list refreshes automatically
              </Typography>
            ) : null}
          </Stack>
        </Box>

        {/* 3. All Scans */}
        <Box>
          <SectionHeader title={`All scans (${scans.length})`} noPadding />
          <SimpleTable
            data={scans}
            columns={[
              {
                label: 'Scanner',
                getter: (s: ScanSummary) => (s.scanner === 'trivy' ? 'Trivy' : s.scanner),
              },
              {
                label: 'Variant',
                getter: (s: ScanSummary) => VARIANT_LABEL[s.variant ?? ''] ?? s.variant ?? '—',
              },
              { label: 'Status', getter: (s: ScanSummary) => statusChip(s.status) },
              { label: 'Started', getter: (s: ScanSummary) => fmtDate(s.started_at) },
              { label: 'Severity counts', getter: countsCell },
              {
                label: '',
                gridTemplate: 'min-content',
                getter: (s: ScanSummary) => (
                  <Tooltip title="Delete this scan (frees storage + updates totals)">
                    <IconButton
                      size="small"
                      aria-label="delete scan"
                      onClick={() => setToDelete(s)}
                    >
                      <Icon icon="mdi:trash-can-outline" width={18} height={18} />
                    </IconButton>
                  </Tooltip>
                ),
              },
            ]}
            emptyMessage={
              loading ? 'Loading scans…' : 'No scans yet — launch one above to scan this cluster.'
            }
          />
        </Box>
      </Stack>

      <Dialog open={toDelete !== null} onClose={() => (deleting ? null : setToDelete(null))}>
        <DialogTitle>Delete this scan?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Permanently remove the {toDelete ? VARIANT_LABEL[toDelete.variant ?? ''] ?? toDelete.variant : ''}{' '}
            scan from {fmtDate(toDelete?.started_at ?? null)} and its findings from persistent
            storage. Its counts will be subtracted from the rolled-up totals. This cannot be undone.
          </DialogContentText>
          {deleteError ? (
            <Alert severity="error" sx={{ mt: 1 }}>
              {deleteError}
            </Alert>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setToDelete(null)} disabled={deleting}>
            Cancel
          </Button>
          <Button onClick={confirmDelete} disabled={deleting} variant="contained" color="error">
            {deleting ? 'Deleting…' : 'Yes, delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </SectionBox>
  );
}

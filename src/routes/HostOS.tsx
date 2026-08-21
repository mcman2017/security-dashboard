// Security Scans → Host OS.
//
// Tab 1 (default): Lynis host audits — backend-orchestrated scans (one
// privileged Job per cluster node) launched from here or by the daily
// schedule, with parsed findings. Rows navigate to the per-scan detail page.
// Tab 2: raw per-node logs of the optional trivy-host-scanner DaemonSet
// (chart value hostScanners.trivyRootfs), read straight from the pods.
import { Icon } from '@iconify/react';
import { CommonComponents, K8s } from '@kinvolk/headlamp-plugin/lib';
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
  MenuItem,
  Select,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from '@mui/material';
import { ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useHistory } from 'react-router';
import { SeverityBadge } from '../components/SeverityBadge';
import { scansApi, ScanSummary } from '../lib/api';
import { SCANS_PATHS, useClusterUrl } from '../lib/nav';
import { SEVERITY_ORDER, severityLabel } from '../lib/severity';
import { usePolling } from '../lib/usePolling';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

// Namespace where the optional trivy-host-scanner DaemonSet runs — see
// docs/host-scans.md (chart value hostScanners.namespace).
const SCANNERS_NAMESPACE = 'trivy-system';

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
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

// ---------------------------------------------------------------------------
// Lynis host audits (backend-orchestrated)
// ---------------------------------------------------------------------------

function LynisPanel() {
  const history = useHistory();
  const build = useClusterUrl();
  const { data, error, loading, refetch } = usePolling(scansApi.list, 5000);

  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [toDelete, setToDelete] = useState<ScanSummary | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const scans = useMemo(
    () => (data?.scans ?? []).filter(s => s.scanner === 'lynis'),
    [data]
  );
  const anyRunning = scans.some(s => s.status === 'running' || s.status === 'pending');

  async function launch() {
    setLaunching(true);
    setLaunchError(null);
    try {
      await scansApi.launch('lynis');
      await refetch();
    } catch (e: any) {
      setLaunchError(e?.message ? String(e.message) : 'launch failed');
    } finally {
      setLaunching(false);
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
    <Stack spacing={3}>
      <Typography variant="body2" color="text.secondary">
        Each audit runs Lynis on every cluster node (one privileged Job per node, control-plane
        included) and parses the reports into findings: warnings, suggestions, and a per-node
        hardening index. Click a scan to see its findings and the raw reports.
      </Typography>

      {error ? (
        <Alert severity="error">
          Could not reach the scan backend (security-dashboard-api). Details:{' '}
          {String((error as any)?.message ?? error)}
        </Alert>
      ) : null}
      {launchError ? <Alert severity="error">{launchError}</Alert> : null}

      <Stack direction="row" spacing={2} alignItems="center">
        <Button
          variant="contained"
          disabled={launching || anyRunning}
          startIcon={
            launching ? (
              <CircularProgress size={16} color="inherit" />
            ) : (
              <Icon icon="mdi:server-network-outline" width={18} height={18} />
            )
          }
          onClick={launch}
        >
          Audit all nodes now
        </Button>
        {anyRunning ? (
          <Typography variant="body2" color="text.secondary">
            an audit is running — this list refreshes automatically
          </Typography>
        ) : null}
      </Stack>

      <SimpleTable
        data={scans}
        columns={[
          { label: 'Status', getter: (s: ScanSummary) => statusChip(s.status) },
          { label: 'Started', getter: (s: ScanSummary) => fmtDate(s.started_at) },
          { label: 'Finished', getter: (s: ScanSummary) => fmtDate(s.finished_at) },
          { label: 'Severity counts', getter: countsCell },
          {
            label: '',
            gridTemplate: 'min-content',
            getter: (s: ScanSummary) => (
              <Stack direction="row" spacing={0}>
                <Tooltip title="View findings and raw reports">
                  <IconButton
                    size="small"
                    aria-label="open scan"
                    onClick={() => history.push(build(`${SCANS_PATHS.hostOs}/scan/${s.id}`))}
                  >
                    <Icon icon="mdi:open-in-new" width={18} height={18} />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Delete this scan">
                  <IconButton
                    size="small"
                    aria-label="delete scan"
                    onClick={e => {
                      e.stopPropagation();
                      setToDelete(s);
                    }}
                  >
                    <Icon icon="mdi:trash-can-outline" width={18} height={18} />
                  </IconButton>
                </Tooltip>
              </Stack>
            ),
          },
        ]}
        emptyMessage={
          loading
            ? 'Loading scans…'
            : 'No host audits yet — launch one above, or enable the daily schedule (chart value lynis.schedule).'
        }
      />

      <Dialog open={toDelete !== null} onClose={() => (deleting ? null : setToDelete(null))}>
        <DialogTitle>Delete this host audit?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Permanently remove the Lynis audit from {fmtDate(toDelete?.started_at ?? null)} and
            its findings from persistent storage. This cannot be undone.
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
    </Stack>
  );
}

// ---------------------------------------------------------------------------
// trivy rootfs DaemonSet log viewer (optional; hostScanners.trivyRootfs)
// ---------------------------------------------------------------------------

interface PodRef {
  name: string;
  node: string;
  phase: string;
  instance: any;
}

function usePodsByLabel(labelSelector: string): PodRef[] {
  const Pod = K8s.ResourceClasses.Pod;
  const [items] = Pod.useList({ namespace: SCANNERS_NAMESPACE } as any);
  return useMemo(() => {
    if (!items) return [];
    const kv = labelSelector.split(',').map(s => s.split('='));
    const filt = (items as any[]).filter(p => {
      const labels = p.jsonData?.metadata?.labels ?? p.metadata?.labels ?? {};
      return kv.every(([k, v]) => labels[k] === v);
    });
    return filt.map(p => ({
      name: p.jsonData?.metadata?.name ?? p.metadata?.name,
      node: p.jsonData?.spec?.nodeName ?? p.spec?.nodeName ?? '?',
      phase: p.jsonData?.status?.phase ?? p.status?.phase ?? '?',
      instance: p,
    }));
  }, [items, labelSelector]);
}

interface PodLogProps {
  pod: PodRef | null;
  container: string;
  tailLines: number;
  emptyHint?: string;
}

/**
 * Streams logs from a single pod via Headlamp's Pod.getLogs helper.
 * Uses the newGetLogs signature: (container, callback, logOptions).
 * Cancels & re-subscribes on pod change.
 */
function PodLogView({ pod, container, tailLines, emptyHint }: PodLogProps) {
  const [text, setText] = useState<string>('');
  const [err, setErr] = useState<string>('');
  const cancelRef = useRef<(() => void) | null>(null);
  const reloadId = useRef(0);

  const subscribe = () => {
    setErr('');
    setText('Loading…');
    cancelRef.current?.();
    cancelRef.current = null;
    if (!pod) return;
    const id = ++reloadId.current;
    try {
      const cancel = pod.instance.getLogs(
        container,
        (result: { logs: string[]; hasJsonLogs?: boolean }) => {
          if (id !== reloadId.current) return;
          const joined = Array.isArray(result?.logs) ? result.logs.join('') : '';
          setText(joined || '(empty)');
        },
        { tailLines, showTimestamps: false, follow: false }
      );
      cancelRef.current = typeof cancel === 'function' ? cancel : null;
    } catch (e: any) {
      setErr(String(e?.message ?? e));
      setText('');
    }
  };

  useEffect(() => {
    subscribe();
    return () => {
      cancelRef.current?.();
      cancelRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pod?.name, container, tailLines]);

  return (
    <Stack spacing={1}>
      <Stack direction="row" spacing={1}>
        <Button variant="outlined" size="small" onClick={subscribe} disabled={!pod}>
          Refresh
        </Button>
        {pod ? <Typography variant="caption">{pod.name} · node {pod.node} · {pod.phase}</Typography> : null}
      </Stack>
      {err ? (
        <Box sx={{ color: '#c62828', fontFamily: 'monospace', fontSize: 12 }}>Failed to load logs: {err}</Box>
      ) : null}
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
        {text || emptyHint || '(no logs)'}
      </Box>
    </Stack>
  );
}

function TrivyHostPanel() {
  const pods = usePodsByLabel('app=trivy-host-scanner');
  const [podName, setPodName] = useState<string>('');
  useEffect(() => {
    if (!podName && pods.length > 0) setPodName(pods[0].name);
  }, [pods, podName]);
  const pod = pods.find(p => p.name === podName) || null;

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={2} alignItems="center">
        <Typography>Node:</Typography>
        <Select size="small" value={podName} onChange={e => setPodName(String(e.target.value))} sx={{ minWidth: 320 }}>
          {pods.map(p => (
            <MenuItem key={p.name} value={p.name}>
              {p.node} ({p.phase}) — {p.name}
            </MenuItem>
          ))}
        </Select>
      </Stack>
      <PodLogView
        pod={pod}
        container="trivy"
        tailLines={500}
        emptyHint="(no trivy-host-scanner pods — enable the DaemonSet via chart value hostScanners.trivyRootfs)"
      />
    </Stack>
  );
}

export function HostOS() {
  const [tab, setTab] = useState(0);
  return (
    <SectionBox title={<SectionHeader title="Host OS scanners" />}>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Lynis host audit (all nodes)" />
        <Tab label="trivy rootfs (per-node, daily)" />
      </Tabs>
      {tab === 0 ? <LynisPanel /> : <TrivyHostPanel />}
    </SectionBox>
  );
}

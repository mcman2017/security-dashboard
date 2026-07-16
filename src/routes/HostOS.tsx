import { CommonComponents, K8s } from '@kinvolk/headlamp-plugin/lib';
import { Box, Button, MenuItem, Select, Stack, Tab, Tabs, Typography } from '@mui/material';
import { useEffect, useMemo, useRef, useState } from 'react';

const { SectionBox, SectionHeader } = CommonComponents;

// Namespace where the host-OS scanner workloads (trivy-host-scanner DaemonSet,
// lynis-host-audit CronJob) run — see docs/host-scans.md.
const SCANNERS_NAMESPACE = 'trivy-system';

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
      <PodLogView pod={pod} container="trivy" tailLines={500} />
    </Stack>
  );
}

function LynisPanel() {
  const pods = usePodsByLabel('app=lynis-host-audit');
  const sorted = useMemo(() => [...pods].sort((a, b) => b.name.localeCompare(a.name)), [pods]);
  const [podName, setPodName] = useState<string>('');
  useEffect(() => {
    if (!podName && sorted.length > 0) setPodName(sorted[0].name);
  }, [sorted, podName]);
  const pod = sorted.find(p => p.name === podName) || null;
  const hint =
    '(no Lynis runs found — deploy the lynis-host-audit CronJob (see docs/host-scans.md), ' +
    `or trigger a manual run: kubectl create job --from=cronjob/lynis-host-audit lynis-manual -n ${SCANNERS_NAMESPACE})`;

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={2} alignItems="center">
        <Typography>Run:</Typography>
        <Select size="small" value={podName} onChange={e => setPodName(String(e.target.value))} sx={{ minWidth: 320 }}>
          {sorted.map(p => (
            <MenuItem key={p.name} value={p.name}>
              {p.name} ({p.phase})
            </MenuItem>
          ))}
        </Select>
      </Stack>
      <PodLogView pod={pod} container="lynis" tailLines={800} emptyHint={hint} />
    </Stack>
  );
}

export function HostOS() {
  const [tab, setTab] = useState(0);
  return (
    <SectionBox title={<SectionHeader title="Host OS scanners" />}>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="trivy rootfs (per-node, daily)" />
        <Tab label="Lynis audit (daily)" />
      </Tabs>
      {tab === 0 ? <TrivyHostPanel /> : <LynisPanel />}
    </SectionBox>
  );
}

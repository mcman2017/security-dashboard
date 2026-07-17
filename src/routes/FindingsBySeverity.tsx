// "Click 684 Critical → see those 684 findings." Reached from the Overview
// rolled-up stat cards (`/security-scans/findings?severity=CRITICAL`). Lists
// every finding of one severity across all completed scans, served by the
// dash backend's /findings/by-severity/:sev endpoint.
import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { Alert, Box, Link as MuiLink, Stack, Typography } from '@mui/material';
import { useMemo } from 'react';
import { useHistory } from 'react-router';
import { Link as RouterLink } from 'react-router-dom';
import { SeverityBadge } from '../components/SeverityBadge';
import { SortableFindingsTable } from '../components/SortableFindingsTable';
import { FindingWithScan, scansApi } from '../lib/api';
import { SCANS_PATHS, useClusterUrl, useSeverityFilter } from '../lib/nav';
import { fromTrivy, SeverityLabel } from '../lib/severity';
import { usePolling } from '../lib/usePolling';

const { SectionBox, SectionHeader } = CommonComponents;

export function FindingsBySeverity() {
  const sev = useSeverityFilter(); // SeverityLabel | null (from ?severity=)
  const build = useClusterUrl();
  const history = useHistory();
  const label = (sev ?? 'CRITICAL') as SeverityLabel;

  const { data, error, loading } = usePolling(
    () => scansApi.findingsBySeverity(label),
    10000
  );

  const findings = useMemo(() => data?.findings ?? [], [data]);
  const total = data?.total ?? 0;
  const scanCount = useMemo(() => new Set(findings.map(f => f.scan.id)).size, [findings]);

  const openFinding = (f: FindingWithScan) => {
    // Old backends don't serve finding ids yet — leave the row inert.
    if (f.id === undefined) return;
    history.push(build(`/security-scans/finding/${f.id}`));
  };

  if (!sev) {
    return (
      <SectionBox title={<SectionHeader title="Findings" />}>
        <Alert severity="warning">
          No severity selected. Open this page from a card on the{' '}
          <MuiLink component={RouterLink} to={build(SCANS_PATHS.overview)}>
            Security overview
          </MuiLink>
          .
        </Alert>
      </SectionBox>
    );
  }

  return (
    <SectionBox
      title={
        <SectionHeader
          title={`${label} findings`}
          actions={[
            <MuiLink key="back" component={RouterLink} to={build(SCANS_PATHS.overview)}>
              ← Security overview
            </MuiLink>,
          ]}
        />
      }
    >
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <SeverityBadge severity={fromTrivy(label)} />
          <Typography variant="body2" color="text.secondary">
            {total} total · across {scanCount} completed scan{scanCount === 1 ? '' : 's'}
          </Typography>
        </Box>

        {error ? (
          <Alert severity="error">
            Failed to load findings: {String((error as any)?.message ?? error)}
          </Alert>
        ) : null}

        <SortableFindingsTable
          findings={findings}
          onRowClick={openFinding}
          emptyMessage={
            loading ? 'Loading findings…' : `No ${label} findings across any completed scan.`
          }
        />
      </Stack>
    </SectionBox>
  );
}

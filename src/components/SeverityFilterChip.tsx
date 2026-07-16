import { Chip, Stack, Typography } from '@mui/material';
import { useHistory } from 'react-router';
import { useClusterUrl, useSeverityFilter } from '../lib/nav';
import { SeverityLabel } from '../lib/severity';

interface Props {
  basePath: string;
}

/**
 * Renders "Filter: CRITICAL ✕" when ?severity= is set in the URL, with a
 * click handler to clear the filter (returns to the unfiltered view).
 */
export function SeverityFilterChip({ basePath }: Props) {
  const sev = useSeverityFilter();
  const history = useHistory();
  const build = useClusterUrl();
  if (!sev) return null;
  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
      <Typography variant="caption" sx={{ color: '#777' }}>
        Filtered to:
      </Typography>
      <Chip
        label={`${sev} ✕`}
        size="small"
        onClick={() => history.push(build(basePath))}
        sx={{ cursor: 'pointer', fontWeight: 600 }}
      />
    </Stack>
  );
}

export function matchesSeverityFilter(rawSeverity: string | undefined, filter: SeverityLabel | null): boolean {
  if (!filter) return true;
  return (rawSeverity || '').toUpperCase() === filter;
}

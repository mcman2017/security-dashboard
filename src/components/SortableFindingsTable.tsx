// Findings table with click-to-sort headers and clickable rows. Replaces
// Headlamp's SimpleTable on the by-severity pages: SimpleTable sorts fine but
// offers no row-click hook, and the detail page needs whole-row navigation.
// Sorting is applied to the FULL findings array before pagination, so ordering
// spans every finding in the bucket, not just the visible page.
//
// Header clicks cycle ascending → descending → unsorted (original order).
// Callers pick which columns to show via `columns`; the default set matches
// the cross-scanner by-severity page.
import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TableSortLabel,
  Typography,
} from '@mui/material';
import { ReactNode, useMemo, useState } from 'react';
import { FindingWithScan } from '../lib/api';
import { Severity } from '../lib/severity';
import { SeverityBadge } from './SeverityBadge';

export function resourceOf(f: FindingWithScan): string {
  const parts = [f.resource_ns, f.resource_kind, f.resource_name].filter(Boolean);
  if (f.image) parts.push(f.image);
  return parts.join('/') || '—';
}

export type FindingsColumnKey = 'severity' | 'id' | 'title' | 'resource' | 'node' | 'original' | 'scan';

const DEFAULT_COLUMNS: FindingsColumnKey[] = ['id', 'title', 'resource', 'original', 'scan'];

const COLUMN_LABEL: Record<FindingsColumnKey, string> = {
  severity: 'Severity',
  id: 'ID',
  title: 'Title',
  resource: 'Resource',
  node: 'Node',
  original: 'Original',
  scan: 'Scan',
};

const COMPARATORS: Record<FindingsColumnKey, (a: FindingWithScan, b: FindingWithScan) => number> = {
  severity: (a, b) => a.severity_normalized - b.severity_normalized,
  id: (a, b) => (a.scanner_id ?? a.control_id ?? '').localeCompare(b.scanner_id ?? b.control_id ?? ''),
  title: (a, b) => a.title.localeCompare(b.title),
  resource: (a, b) => resourceOf(a).localeCompare(resourceOf(b)),
  node: (a, b) => (a.resource_name ?? '').localeCompare(b.resource_name ?? ''),
  original: (a, b) => (a.severity_original || '').localeCompare(b.severity_original || ''),
  scan: (a, b) =>
    `${a.scan.scanner} ${a.scan.variant ?? ''}`.localeCompare(`${b.scan.scanner} ${b.scan.variant ?? ''}`),
};

function cellFor(key: FindingsColumnKey, f: FindingWithScan): ReactNode {
  switch (key) {
    case 'severity':
      return <SeverityBadge severity={f.severity_normalized as Severity} />;
    case 'id':
      return f.scanner_id ?? f.control_id ?? '—';
    case 'title':
      return f.title;
    case 'resource':
      return resourceOf(f);
    case 'node':
      return f.resource_name ?? '—';
    case 'original':
      return f.severity_original || '—';
    case 'scan':
      return (
        <Typography variant="caption" color="text.secondary">
          {f.scan.scanner}
          {f.scan.variant ? ` · ${f.scan.variant}` : ''}
        </Typography>
      );
  }
}

interface Props {
  findings: FindingWithScan[];
  emptyMessage: string;
  onRowClick: (f: FindingWithScan) => void;
  columns?: FindingsColumnKey[];
}

export function SortableFindingsTable({ findings, emptyMessage, onRowClick, columns }: Props) {
  const cols = columns ?? DEFAULT_COLUMNS;
  const [orderBy, setOrderBy] = useState<FindingsColumnKey | null>(null);
  const [order, setOrder] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const sorted = useMemo(() => {
    if (!orderBy) return findings;
    const cmp = COMPARATORS[orderBy];
    const out = findings.slice().sort(cmp);
    if (order === 'desc') out.reverse();
    return out;
  }, [findings, orderBy, order]);

  // Clamp instead of trusting `page`: the polling refetch can shrink the list
  // (scan deleted) while the user sits on a late page.
  const safePage = Math.min(page, Math.max(0, Math.ceil(sorted.length / rowsPerPage) - 1));
  const pageRows = sorted.slice(safePage * rowsPerPage, (safePage + 1) * rowsPerPage);

  // Three-state cycle per column: unsorted → asc → desc → unsorted.
  const handleSort = (key: FindingsColumnKey) => {
    if (orderBy !== key) {
      setOrderBy(key);
      setOrder('asc');
    } else if (order === 'asc') {
      setOrder('desc');
    } else {
      setOrderBy(null);
      setOrder('asc');
    }
    setPage(0);
  };

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            {cols.map(key => (
              <TableCell key={key} sortDirection={orderBy === key ? order : false}>
                <TableSortLabel
                  active={orderBy === key}
                  direction={orderBy === key ? order : 'asc'}
                  onClick={() => handleSort(key)}
                >
                  {COLUMN_LABEL[key]}
                </TableSortLabel>
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {pageRows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={cols.length}>
                <Typography variant="body2" color="text.secondary" align="center" sx={{ py: 2 }}>
                  {emptyMessage}
                </Typography>
              </TableCell>
            </TableRow>
          ) : (
            pageRows.map((f, i) => (
              <TableRow
                key={f.id ?? `${f.scan.id}-${i}`}
                hover
                onClick={() => onRowClick(f)}
                sx={{ cursor: 'pointer' }}
              >
                {cols.map(key => (
                  <TableCell key={key} sx={key === 'resource' ? { wordBreak: 'break-all' } : undefined}>
                    {cellFor(key, f)}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
      <TablePagination
        component="div"
        count={sorted.length}
        page={safePage}
        rowsPerPage={rowsPerPage}
        rowsPerPageOptions={[25, 50, 100]}
        onPageChange={(_e, p) => setPage(p)}
        onRowsPerPageChange={e => {
          setRowsPerPage(parseInt(e.target.value, 10));
          setPage(0);
        }}
      />
    </TableContainer>
  );
}

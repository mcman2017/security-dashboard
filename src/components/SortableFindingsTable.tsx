// Findings table with click-to-sort headers and clickable rows. Replaces
// Headlamp's SimpleTable on the by-severity pages: SimpleTable sorts fine but
// offers no row-click hook, and the detail page needs whole-row navigation.
// Sorting is applied to the FULL findings array before pagination, so ordering
// spans every finding in the bucket, not just the visible page.
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
import { useMemo, useState } from 'react';
import { FindingWithScan } from '../lib/api';

export function resourceOf(f: FindingWithScan): string {
  const parts = [f.resource_ns, f.resource_kind, f.resource_name].filter(Boolean);
  if (f.image) parts.push(f.image);
  return parts.join('/') || '—';
}

type ColumnKey = 'id' | 'title' | 'resource' | 'original' | 'scan';

const COLUMNS: Array<{ key: ColumnKey; label: string }> = [
  { key: 'id', label: 'ID' },
  { key: 'title', label: 'Title' },
  { key: 'resource', label: 'Resource' },
  { key: 'original', label: 'Original' },
  { key: 'scan', label: 'Scan' },
];

const COMPARATORS: Record<ColumnKey, (a: FindingWithScan, b: FindingWithScan) => number> = {
  id: (a, b) => (a.scanner_id ?? a.control_id ?? '').localeCompare(b.scanner_id ?? b.control_id ?? ''),
  title: (a, b) => a.title.localeCompare(b.title),
  resource: (a, b) => resourceOf(a).localeCompare(resourceOf(b)),
  original: (a, b) => (a.severity_original || '').localeCompare(b.severity_original || ''),
  scan: (a, b) =>
    `${a.scan.scanner} ${a.scan.variant ?? ''}`.localeCompare(`${b.scan.scanner} ${b.scan.variant ?? ''}`),
};

interface Props {
  findings: FindingWithScan[];
  emptyMessage: string;
  onRowClick: (f: FindingWithScan) => void;
}

export function SortableFindingsTable({ findings, emptyMessage, onRowClick }: Props) {
  const [orderBy, setOrderBy] = useState<ColumnKey | null>(null);
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

  const handleSort = (key: ColumnKey) => {
    if (orderBy === key) {
      setOrder(o => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setOrderBy(key);
      setOrder('asc');
    }
    setPage(0);
  };

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            {COLUMNS.map(col => (
              <TableCell key={col.key} sortDirection={orderBy === col.key ? order : false}>
                <TableSortLabel
                  active={orderBy === col.key}
                  direction={orderBy === col.key ? order : 'asc'}
                  onClick={() => handleSort(col.key)}
                >
                  {col.label}
                </TableSortLabel>
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {pageRows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={COLUMNS.length}>
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
                <TableCell>{f.scanner_id ?? f.control_id ?? '—'}</TableCell>
                <TableCell>{f.title}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>{resourceOf(f)}</TableCell>
                <TableCell>{f.severity_original || '—'}</TableCell>
                <TableCell>
                  <Typography variant="caption" color="text.secondary">
                    {f.scan.scanner}
                    {f.scan.variant ? ` · ${f.scan.variant}` : ''}
                  </Typography>
                </TableCell>
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

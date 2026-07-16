import { CommonComponents } from '@kinvolk/headlamp-plugin/lib';
import { allSuppressions } from '../lib/suppressions';

const { SectionBox, SectionHeader, SimpleTable } = CommonComponents;

const reasonColor: Record<string, string> = {
  'built-in-k8s': '#1976d2',
  'vendor-helm': '#7b1fa2',
  'app-by-design': '#388e3c',
  'static-by-design': '#388e3c',
  unspecified: '#616161',
};

export function Suppressions() {
  const rows = allSuppressions();
  return (
    <SectionBox
      title={
        <SectionHeader
          title={`Suppression allowlist (${rows.length})`}
          actions={[]}
        />
      }
    >
      <p style={{ marginTop: 0, color: '#777' }}>
        Findings matching any entry below are bucketed as <b>SUPPRESSED</b> in the
        other Security pages — the underlying CRD report is preserved unchanged
        in the cluster, so an audit can always inspect the raw severity. See{' '}
        <code>docs/suppressions.md</code> for the file format and how to maintain
        your own allowlist.
      </p>
      <SimpleTable
        data={rows}
        columns={[
          {
            label: 'Reason',
            getter: (r: any) => (
              <span
                style={{
                  backgroundColor: reasonColor[r.reason] || '#616161',
                  color: '#fff',
                  padding: '2px 8px',
                  borderRadius: 4,
                  fontSize: 12,
                  fontWeight: 600,
                }}
              >
                {r.reason}
              </span>
            ),
          },
          { label: 'AVD ID', getter: (r: any) => r.avd_id },
          { label: 'Target kind', getter: (r: any) => r.target_kind },
          {
            label: 'Target name / pattern',
            getter: (r: any) => r.target_name || r.target_name_pattern,
          },
          { label: 'Justification', getter: (r: any) => r.justification },
        ]}
      />
    </SectionBox>
  );
}

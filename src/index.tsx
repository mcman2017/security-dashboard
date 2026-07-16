// Security-Scans plugin entrypoint — registers a "Security Scans" sidebar
// parent (distinct from Headlamp's built-in "Security" entry whose name is
// also `security` and shows ServiceAccounts/Roles/RoleBindings) and 8 child
// routes that surface Trivy Operator CRDs + the host-OS scanner stdout.

import { registerRoute, registerSidebarEntry } from '@kinvolk/headlamp-plugin/lib';
import { Compliance } from './routes/Compliance';
import { Configuration } from './routes/Configuration';
import { FindingsBySeverity } from './routes/FindingsBySeverity';
import { HostOS } from './routes/HostOS';
import { Overview } from './routes/Overview';
import { Rbac } from './routes/Rbac';
import { ScanDetail } from './routes/ScanDetail';
import { Secrets } from './routes/Secrets';
import { Suppressions } from './routes/Suppressions';
import { Vulnerabilities } from './routes/Vulnerabilities';

const PARENT = 'security-scans';
const BASE = '/security-scans';

// ---- Sidebar (single parent + 8 children) ----
registerSidebarEntry({
  parent: null,
  name: PARENT,
  label: 'Security Scans',
  icon: 'mdi:shield-search',
  url: BASE,
  useClusterURL: true,
});

const children: Array<{ name: string; label: string; path: string; icon: string }> = [
  { name: 'security-scans-overview',     label: 'Overview',        path: '',                  icon: 'mdi:view-dashboard-outline' },
  { name: 'security-scans-vulns',        label: 'Vulnerabilities', path: '/vulnerabilities',  icon: 'mdi:bug-outline' },
  { name: 'security-scans-config',       label: 'Configuration',   path: '/configuration',    icon: 'mdi:cog-outline' },
  { name: 'security-scans-rbac',         label: 'RBAC',            path: '/rbac',             icon: 'mdi:account-key-outline' },
  { name: 'security-scans-compliance',   label: 'Compliance',      path: '/compliance',       icon: 'mdi:clipboard-check-outline' },
  { name: 'security-scans-secrets',      label: 'Exposed Secrets', path: '/secrets',          icon: 'mdi:key-alert-outline' },
  { name: 'security-scans-host',         label: 'Host OS',         path: '/host-os',          icon: 'mdi:server-network-outline' },
  { name: 'security-scans-suppressions', label: 'Suppressions',    path: '/suppressions',     icon: 'mdi:filter-off-outline' },
];

for (const c of children) {
  registerSidebarEntry({
    parent: PARENT,
    name: c.name,
    label: c.label,
    icon: c.icon,
    url: `${BASE}${c.path}`,
    useClusterURL: true,
  });
}

// ---- Routes ----
// Per the Headlamp sidebar example: `sidebar:` on a Route is the *name* of
// the sidebar entry to highlight when the route is active. Using the simple
// string form lets Headlamp keep the route on the default (IN-CLUSTER)
// sidebar — the {item, sidebar: 'HOME'} object form moved them to the
// pre-login HOME sidebar and broke navigation.
registerRoute({
  path: BASE,
  exact: true,
  sidebar: 'security-scans-overview',
  name: 'Security Overview',
  component: Overview,
});
registerRoute({
  path: `${BASE}/vulnerabilities`,
  exact: true,
  sidebar: 'security-scans-vulns',
  name: 'Vulnerabilities',
  component: Vulnerabilities,
});
registerRoute({
  path: `${BASE}/configuration`,
  exact: true,
  sidebar: 'security-scans-config',
  name: 'Configuration audit',
  component: Configuration,
});
registerRoute({
  path: `${BASE}/rbac`,
  exact: true,
  sidebar: 'security-scans-rbac',
  name: 'RBAC',
  component: Rbac,
});
registerRoute({
  path: `${BASE}/compliance`,
  exact: true,
  sidebar: 'security-scans-compliance',
  name: 'Compliance',
  component: Compliance,
});
registerRoute({
  path: `${BASE}/secrets`,
  exact: true,
  sidebar: 'security-scans-secrets',
  name: 'Exposed secrets',
  component: Secrets,
});
registerRoute({
  path: `${BASE}/host-os`,
  exact: true,
  sidebar: 'security-scans-host',
  name: 'Host OS',
  component: HostOS,
});
registerRoute({
  path: `${BASE}/suppressions`,
  exact: true,
  sidebar: 'security-scans-suppressions',
  name: 'Suppressions',
  component: Suppressions,
});
// Per-scan detail page — clicked from the Overview's Scans table. Highlights
// the parent Overview entry in the sidebar (no separate sidebar item).
registerRoute({
  path: `${BASE}/scan/:scanner/:ns/:name`,
  exact: true,
  sidebar: 'security-scans-overview',
  name: 'Scan detail',
  component: ScanDetail,
});
// Findings-by-severity drill-down — reached from the Overview rolled-up stat
// cards via ?severity=. Highlights the Overview sidebar entry.
registerRoute({
  path: `${BASE}/findings`,
  exact: true,
  sidebar: 'security-scans-overview',
  name: 'Findings by severity',
  component: FindingsBySeverity,
});

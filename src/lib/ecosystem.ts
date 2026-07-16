// Ecosystem-vs-workload classification — port of api/src/sec_dashboard/scans/parsers/trivy.py.
//
// "Ecosystem" findings come from system components we don't own (kube-system,
// cert-manager, ingress-nginx, kube-flannel, rook-ceph, etc.) or images that
// are upstream-managed (k8s.gcr.io, registry.k8s.io, ghcr.io/aquasecurity).
// "Workload" findings come from user-owned workloads — that's where action is
// most likely needed.

const ECOSYSTEM_NAMESPACES = new Set([
  'kube-system',
  'kube-public',
  'kube-node-lease',
  'cert-manager',
  'ingress-nginx',
  'kube-flannel',
  'metallb-system',
  'rook-ceph',
  'trivy-system',
  'kubernetes-dashboard',
]);

const ECOSYSTEM_IMAGE_PREFIXES = [
  'k8s.gcr.io/',
  'registry.k8s.io/',
  'ghcr.io/aquasecurity/',
  'ghcr.io/aquasec/',
  'docker.io/aquasec/',
  'aquasec/',
  'mirror.gcr.io/aquasec/',
  'quay.io/cilium/',
  'quay.io/jetstack/',
  'quay.io/metallb/',
  'quay.io/cephcsi/',
  'rook/',
  'docker.io/rancher/',
  'rancher/',
];

export function isEcosystemNamespace(ns: string | undefined): boolean {
  return !!ns && ECOSYSTEM_NAMESPACES.has(ns);
}

export function isEcosystemImage(image: string | undefined): boolean {
  if (!image) return false;
  return ECOSYSTEM_IMAGE_PREFIXES.some(p => image.startsWith(p));
}

export function isEcosystem(opts: { namespace?: string; image?: string }): boolean {
  return isEcosystemNamespace(opts.namespace) || isEcosystemImage(opts.image);
}

// Suppression allowlist — port of api/src/sec_dashboard/scans/suppressions.py.
//
// Loads suppressions.yaml at build time (Vite ?raw import) and exposes
// isSuppressed(...) for client-side rebucketing of findings whose
// (avd_id, target_kind, target_name) triple is on the allowlist.

import yaml from 'js-yaml';
// Vite raw-string import; the YAML file lives under src/data/.
import suppressionsRaw from '../data/suppressions.yaml?raw';

export interface SuppressionEntry {
  avd_id: string;
  target_kind: string;
  target_name?: string;
  target_name_pattern?: string;
  reason: string;
  justification: string;
}

export interface SuppressionMatch {
  matched: boolean;
  reason?: string;
  justification?: string;
  entry?: SuppressionEntry;
}

interface Loaded {
  exact: Map<string, SuppressionEntry>;
  patterns: SuppressionEntry[];
  all: SuppressionEntry[];
}

function key(avd: string, kind: string, name: string): string {
  return `${avd}|${kind}|${name}`;
}

function compile(): Loaded {
  let parsed: unknown;
  try {
    parsed = yaml.load(suppressionsRaw as string);
  } catch (e) {
    console.warn('[security-plugin] failed to parse suppressions.yaml; fail-open:', e);
    return { exact: new Map(), patterns: [], all: [] };
  }
  if (!parsed || typeof parsed !== 'object') return { exact: new Map(), patterns: [], all: [] };
  const root = parsed as { suppressions?: SuppressionEntry[] };
  const entries = Array.isArray(root.suppressions) ? root.suppressions : [];
  const exact = new Map<string, SuppressionEntry>();
  const patterns: SuppressionEntry[] = [];
  for (const e of entries) {
    if (!e?.avd_id || !e?.target_kind) continue;
    const justified: SuppressionEntry = {
      avd_id: e.avd_id,
      target_kind: e.target_kind,
      target_name: e.target_name,
      target_name_pattern: e.target_name_pattern,
      reason: e.reason || 'unspecified',
      justification: (e.justification || '').trim(),
    };
    if (e.target_name_pattern) {
      patterns.push(justified);
    } else if (e.target_name) {
      exact.set(key(e.avd_id, e.target_kind, e.target_name), justified);
    }
  }
  return { exact, patterns, all: entries };
}

const loaded = compile();

// fnmatch-equivalent: '*' matches any chars (incl. /), '?' matches one char,
// '[abc]' matches any of those chars. Lifted from the Python fnmatch semantics.
function fnmatchToRegex(pattern: string): RegExp {
  let r = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') r += '.*';
    else if (c === '?') r += '.';
    else if (c === '[') {
      const end = pattern.indexOf(']', i);
      if (end === -1) r += '\\[';
      else {
        r += '[' + pattern.slice(i + 1, end) + ']';
        i = end;
      }
    } else if ('.+^$()|{}\\'.includes(c)) r += '\\' + c;
    else r += c;
  }
  return new RegExp('^' + r + '$');
}

const patternCache = new Map<string, RegExp>();
function regexFor(p: string): RegExp {
  let r = patternCache.get(p);
  if (!r) {
    r = fnmatchToRegex(p);
    patternCache.set(p, r);
  }
  return r;
}

export function isSuppressed(
  avd_id: string | undefined,
  target_kind: string | undefined,
  target_name: string | undefined
): SuppressionMatch {
  if (!avd_id || !target_kind || !target_name) return { matched: false };
  const direct = loaded.exact.get(key(avd_id, target_kind, target_name));
  if (direct) {
    return { matched: true, reason: direct.reason, justification: direct.justification, entry: direct };
  }
  for (const p of loaded.patterns) {
    if (p.avd_id !== avd_id || p.target_kind !== target_kind) continue;
    if (regexFor(p.target_name_pattern!).test(target_name)) {
      return { matched: true, reason: p.reason, justification: p.justification, entry: p };
    }
  }
  return { matched: false };
}

export function allSuppressions(): SuppressionEntry[] {
  return loaded.all;
}

export function suppressionCount(): number {
  return loaded.exact.size + loaded.patterns.length;
}

// Kubescape control-id -> Trivy AVD mapping (so one allowlist covers both).
export const KUBESCAPE_TO_TRIVY_AVD: Record<string, string> = {
  'C-0035': 'AVD-KSV-0046',
  'C-0044': 'AVD-KSV-0046',
  'C-0053': 'AVD-KSV-0041',
  'C-0270': 'AVD-KSV-0041',
  'C-0271': 'AVD-KSV-0046',
};

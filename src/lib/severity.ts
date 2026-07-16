// Cross-scanner severity normalization. Port of api/src/sec_dashboard/severity.py.
//
// Order: CRITICAL=5 > HIGH=4 > MEDIUM=3 > LOW=2 > INFO=1 > SUPPRESSED=0.

export enum Severity {
  Critical = 5,
  High = 4,
  Medium = 3,
  Low = 2,
  Info = 1,
  Suppressed = 0,
}

export type SeverityLabel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SUPPRESSED';

export const SEVERITY_ORDER: Severity[] = [
  Severity.Critical,
  Severity.High,
  Severity.Medium,
  Severity.Low,
  Severity.Info,
  Severity.Suppressed,
];

export function severityLabel(s: Severity): SeverityLabel {
  switch (s) {
    case Severity.Critical:
      return 'CRITICAL';
    case Severity.High:
      return 'HIGH';
    case Severity.Medium:
      return 'MEDIUM';
    case Severity.Low:
      return 'LOW';
    case Severity.Info:
      return 'INFO';
    case Severity.Suppressed:
      return 'SUPPRESSED';
  }
}

export function severityColor(s: Severity): string {
  switch (s) {
    case Severity.Critical:
      return '#b71c1c';
    case Severity.High:
      return '#e64a19';
    case Severity.Medium:
      return '#f9a825';
    case Severity.Low:
      return '#1976d2';
    case Severity.Info:
      return '#616161';
    case Severity.Suppressed:
      return '#9e9e9e';
  }
}

export function fromTrivy(raw: string | undefined): Severity {
  const s = (raw || '').toUpperCase();
  switch (s) {
    case 'CRITICAL':
      return Severity.Critical;
    case 'HIGH':
      return Severity.High;
    case 'MEDIUM':
      return Severity.Medium;
    case 'LOW':
      return Severity.Low;
    case 'UNKNOWN':
      return Severity.Info;
    default:
      return Severity.Info;
  }
}

export function emptyCounts(): Record<SeverityLabel, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, SUPPRESSED: 0 };
}

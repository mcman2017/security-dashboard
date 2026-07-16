import { Chip } from '@mui/material';
import { Severity, severityColor, severityLabel } from '../lib/severity';

interface Props {
  severity: Severity;
  count?: number;
  onClick?: () => void;
  size?: 'small' | 'medium';
}

export function SeverityBadge({ severity, count, onClick, size = 'small' }: Props) {
  const label = count !== undefined ? `${severityLabel(severity)} · ${count}` : severityLabel(severity);
  return (
    <Chip
      label={label}
      onClick={onClick}
      size={size}
      sx={{
        backgroundColor: severityColor(severity),
        color: '#fff',
        fontWeight: 600,
        cursor: onClick ? 'pointer' : 'default',
      }}
    />
  );
}

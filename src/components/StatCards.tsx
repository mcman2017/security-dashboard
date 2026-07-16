import { Card, CardActionArea, CardContent, Grid, Typography } from '@mui/material';
import { Severity, SEVERITY_ORDER, severityColor, SeverityLabel,severityLabel } from '../lib/severity';

interface Props {
  counts: Record<SeverityLabel, number>;
  onSelect?: (s: Severity) => void;
  highlighted?: Severity;
}

export function StatCards({ counts, onSelect, highlighted }: Props) {
  return (
    <Grid container spacing={2}>
      {SEVERITY_ORDER.map(s => {
        const label = severityLabel(s);
        const n = counts[label] ?? 0;
        const color = severityColor(s);
        const isHi = highlighted === s;
        const inner = (
          <CardContent sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="caption" sx={{ color, fontWeight: 700, letterSpacing: 0.5 }}>
              {label}
            </Typography>
            <Typography variant="h4" sx={{ color, fontWeight: 700 }}>
              {n}
            </Typography>
          </CardContent>
        );
        return (
          <Grid item key={label} xs={6} sm={4} md={2}>
            <Card
              elevation={isHi ? 6 : 1}
              sx={{
                borderTop: `4px solid ${color}`,
                outline: isHi ? `2px solid ${color}` : 'none',
              }}
            >
              {onSelect ? (
                <CardActionArea onClick={() => onSelect(s)} aria-label={`Filter ${label}`}>
                  {inner}
                </CardActionArea>
              ) : (
                inner
              )}
            </Card>
          </Grid>
        );
      })}
    </Grid>
  );
}

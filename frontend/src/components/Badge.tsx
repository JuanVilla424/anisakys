import clsx from 'clsx';

interface BadgeProps {
  children: React.ReactNode;
  variant: 'danger' | 'warning' | 'success' | 'info';
  className?: string;
}

export function Badge({ children, variant, className }: BadgeProps) {
  return (
    <span className={clsx('badge', `badge-${variant}`, className)}>
      {children}
    </span>
  );
}

export function ThreatLevelBadge({ level }: { level: string }) {
  const variantMap = {
    critical: 'danger' as const,
    high: 'danger' as const,
    medium: 'warning' as const,
    low: 'info' as const,
    safe: 'success' as const,
  };

  return (
    <Badge variant={variantMap[level as keyof typeof variantMap] || 'info'}>
      {level.toUpperCase()}
    </Badge>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const variantMap: Record<string, 'danger' | 'warning' | 'success' | 'info'> = {
    pending: 'warning',
    reported: 'info',
    confirmed: 'danger',
    false_positive: 'success',
    sent: 'info',
    acknowledged: 'warning',
    resolved: 'success',
    escalated: 'danger',
    overdue: 'danger',
  };

  return (
    <Badge variant={variantMap[status] || 'info'}>
      {status.replace('_', ' ').toUpperCase()}
    </Badge>
  );
}

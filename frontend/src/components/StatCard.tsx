import { ReactNode } from 'react';
import { LucideIcon } from 'lucide-react';
import clsx from 'clsx';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  color?: 'blue' | 'green' | 'red' | 'yellow' | 'purple';
  subtitle?: string;
}

export function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  color = 'blue',
  subtitle,
}: StatCardProps) {
  return (
    <div className="p-4 border-r border-gray-300 last:border-r-0">
      <div className="text-[10px] uppercase tracking-wide text-gray-500 font-medium mb-2">{title}</div>
      <div className="text-2xl font-semibold text-gray-900 tabular-nums">{value}</div>
      {trend && (
        <div className="text-[10px] text-gray-500 mt-1">
          <span className={trend.isPositive ? 'text-green-600' : 'text-red-600'}>
            {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
          </span> vs last period
        </div>
      )}
    </div>
  );
}

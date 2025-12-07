import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  FileText,
  TrendingUp,
  Clock,
  Shield,
} from 'lucide-react';
import { apiClient } from '@/services/api';
import { StatCard, Card, Loading, ThreatLevelBadge } from '@/components';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { format } from 'date-fns';

export function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiClient.getStats(),
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: chartData } = useQuery({
    queryKey: ['chartData'],
    queryFn: () => apiClient.getChartData('week'),
    refetchInterval: 60000,
  });

  if (isLoading || !stats) {
    return <Loading fullScreen message="Loading dashboard..." />;
  }

  const threatDistributionData = [
    { name: 'Critical', value: stats.threat_distribution.critical, color: '#dc2626' },
    { name: 'High', value: stats.threat_distribution.high, color: '#ea580c' },
    { name: 'Medium', value: stats.threat_distribution.medium, color: '#f59e0b' },
    { name: 'Low', value: stats.threat_distribution.low, color: '#3b82f6' },
  ];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-gray-600">
          Real-time overview of phishing detection and reporting
        </p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
        <StatCard
          title="Total Scans"
          value={stats.total_scans.toLocaleString()}
          icon={Activity}
          color="blue"
          subtitle="All-time scans"
        />
        <StatCard
          title="Active Threats"
          value={stats.active_threats.toLocaleString()}
          icon={AlertTriangle}
          color="red"
          subtitle="Requiring attention"
        />
        <StatCard
          title="Reports Sent"
          value={stats.reports_sent.toLocaleString()}
          icon={FileText}
          color="green"
          subtitle="To abuse contacts"
        />
        <StatCard
          title="Pending Reports"
          value={stats.pending_reports.toLocaleString()}
          icon={Clock}
          color="yellow"
          subtitle="Awaiting response"
        />
        <StatCard
          title="Detection Rate"
          value={`${stats.detection_rate.toFixed(1)}%`}
          icon={TrendingUp}
          color="purple"
          subtitle="Accuracy metric"
        />
        <StatCard
          title="Avg Confidence"
          value={`${stats.avg_confidence_score.toFixed(1)}%`}
          icon={Shield}
          color="blue"
          subtitle="Across all detections"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Activity timeline */}
        <Card title="Activity Timeline" subtitle="Last 7 days">
          {chartData && chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="date"
                  tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(date) => format(new Date(date), 'MMM dd, yyyy')}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="scans"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  name="Scans"
                />
                <Line
                  type="monotone"
                  dataKey="detections"
                  stroke="#ef4444"
                  strokeWidth={2}
                  name="Detections"
                />
                <Line
                  type="monotone"
                  dataKey="reports"
                  stroke="#22c55e"
                  strokeWidth={2}
                  name="Reports"
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px]">
              <p className="text-gray-500">No data available</p>
            </div>
          )}
        </Card>

        {/* Threat distribution */}
        <Card title="Threat Distribution" subtitle="By severity level">
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={threatDistributionData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) =>
                  `${name} ${(percent * 100).toFixed(0)}%`
                }
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {threatDistributionData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Top keywords and TLDs */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top keywords */}
        <Card title="Top Keywords" subtitle="Most detected patterns">
          <div className="space-y-3">
            {stats.top_keywords.slice(0, 5).map((item, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary-100 text-sm font-semibold text-primary-600">
                    {index + 1}
                  </span>
                  <span className="font-medium text-gray-900">{item.keyword}</span>
                </div>
                <span className="text-lg font-semibold text-gray-600">
                  {item.count}
                </span>
              </div>
            ))}
          </div>
        </Card>

        {/* Top TLDs */}
        <Card title="Top TLDs" subtitle="Most abused domains">
          <div className="space-y-3">
            {stats.top_tlds.slice(0, 5).map((item, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-danger-100 text-sm font-semibold text-danger-600">
                    {index + 1}
                  </span>
                  <span className="font-medium text-gray-900">{item.tld}</span>
                </div>
                <span className="text-lg font-semibold text-gray-600">
                  {item.count}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Recent activity */}
      <Card title="Recent Activity" subtitle="Latest system events">
        <div className="space-y-4">
          {stats.recent_activity.slice(0, 10).map((activity, index) => (
            <div
              key={index}
              className="flex items-start gap-3 border-b border-gray-100 pb-3 last:border-0"
            >
              <div className="mt-1">
                {activity.type === 'scan' && (
                  <Activity className="h-5 w-5 text-blue-500" />
                )}
                {activity.type === 'detection' && (
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                )}
                {activity.type === 'report' && (
                  <FileText className="h-5 w-5 text-green-500" />
                )}
              </div>
              <div className="flex-1">
                <p className="text-sm text-gray-900">{activity.description}</p>
                <p className="mt-1 text-xs text-gray-500">
                  {format(new Date(activity.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                </p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

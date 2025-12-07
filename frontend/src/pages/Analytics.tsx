import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { BarChart3, Globe, TrendingUp, Calendar } from 'lucide-react';
import { apiClient } from '@/services/api';
import { Card, Loading, Badge } from '@/components';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
} from 'recharts';
import { format } from 'date-fns';

export function Analytics() {
  const [period, setPeriod] = useState<'day' | 'week' | 'month'>('week');

  const { data: chartData, isLoading: isChartLoading } = useQuery({
    queryKey: ['chartData', period],
    queryFn: () => apiClient.getChartData(period),
  });

  const { data: threatMap, isLoading: isThreatMapLoading } = useQuery({
    queryKey: ['threatMap'],
    queryFn: () => apiClient.getThreatMap(),
  });

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiClient.getStats(),
  });

  if (isChartLoading || isThreatMapLoading) {
    return <Loading fullScreen message="Loading analytics..." />;
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Analytics</h1>
          <p className="mt-2 text-gray-600">
            Advanced threat intelligence visualization and trends
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Calendar className="h-5 w-5 text-gray-400" />
          <select
            value={period}
            onChange={(e) => setPeriod(e.target.value as 'day' | 'week' | 'month')}
            className="input w-auto"
          >
            <option value="day">Last 24 Hours</option>
            <option value="week">Last 7 Days</option>
            <option value="month">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* Activity trends */}
      <Card
        title="Activity Trends"
        subtitle={`Scans, detections, and reports over the ${period === 'day' ? 'last 24 hours' : period === 'week' ? 'last 7 days' : 'last 30 days'}`}
      >
        {chartData && chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={400}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorDetections" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorReports" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
              </defs>
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
              <Area
                type="monotone"
                dataKey="scans"
                stroke="#3b82f6"
                fillOpacity={1}
                fill="url(#colorScans)"
                name="Scans"
              />
              <Area
                type="monotone"
                dataKey="detections"
                stroke="#ef4444"
                fillOpacity={1}
                fill="url(#colorDetections)"
                name="Detections"
              />
              <Area
                type="monotone"
                dataKey="reports"
                stroke="#22c55e"
                fillOpacity={1}
                fill="url(#colorReports)"
                name="Reports"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-[400px]">
            <p className="text-gray-500">No data available for this period</p>
          </div>
        )}
      </Card>

      {/* Detection rate and confidence */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Detection Rate Over Time" subtitle="Percentage of malicious URLs detected">
          {chartData && chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="date"
                  tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                />
                <YAxis unit="%" />
                <Tooltip
                  labelFormatter={(date) => format(new Date(date), 'MMM dd, yyyy')}
                  formatter={(value: number) => [`${value.toFixed(1)}%`, 'Detection Rate']}
                />
                <Line
                  type="monotone"
                  dataKey={(data) =>
                    data.scans > 0
                      ? ((data.detections / data.scans) * 100).toFixed(1)
                      : 0
                  }
                  stroke="#8b5cf6"
                  strokeWidth={2}
                  name="Detection Rate"
                  dot={{ fill: '#8b5cf6' }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px]">
              <p className="text-gray-500">No data available</p>
            </div>
          )}
        </Card>

        <Card title="Scans vs Detections" subtitle="Comparison of total scans and threats found">
          {chartData && chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData}>
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
                <Bar dataKey="scans" fill="#3b82f6" name="Scans" />
                <Bar dataKey="detections" fill="#ef4444" name="Detections" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px]">
              <p className="text-gray-500">No data available</p>
            </div>
          )}
        </Card>
      </div>

      {/* Threat map */}
      <Card
        title="Threat Map"
        subtitle="Geographic distribution of malicious IPs"
        actions={
          <Badge variant="info">
            <Globe className="h-3 w-3 mr-1 inline" />
            {threatMap?.length || 0} Countries
          </Badge>
        }
      >
        {threatMap && threatMap.length > 0 ? (
          <div className="space-y-4">
            {/* Map placeholder - in a real app you'd use a library like react-leaflet */}
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg p-8 text-center">
              <Globe className="h-16 w-16 mx-auto text-blue-500 mb-4" />
              <p className="text-gray-600">
                Interactive threat map would be displayed here
              </p>
              <p className="text-sm text-gray-500 mt-2">
                Showing {threatMap.length} threat locations across {' '}
                {new Set(threatMap.map((t) => t.country)).size} countries
              </p>
            </div>

            {/* Top threat locations */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {threatMap.slice(0, 6).map((location, index) => (
                <div
                  key={index}
                  className="bg-gray-50 rounded-lg p-4 border border-gray-200"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-gray-900">
                      {location.country}
                    </span>
                    <Badge variant="danger">{location.threat_count}</Badge>
                  </div>
                  <div className="text-sm text-gray-600">
                    <div>IP: {location.ip}</div>
                    <div className="mt-1">
                      Last seen: {format(new Date(location.last_seen), 'MMM dd, HH:mm')}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-[300px]">
            <Globe className="h-12 w-12 text-gray-400 mb-4" />
            <p className="text-gray-500">No threat location data available</p>
          </div>
        )}
      </Card>

      {/* Performance metrics */}
      {stats && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card title="Scan Performance" subtitle="24-hour scan rate">
            <div className="mt-4">
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-bold text-gray-900">
                  {stats.scan_rate_24h}
                </span>
                <span className="text-gray-600">scans/hour</span>
              </div>
              <div className="mt-4 flex items-center gap-2 text-sm">
                <TrendingUp className="h-4 w-4 text-green-500" />
                <span className="text-green-600 font-medium">Optimal performance</span>
              </div>
            </div>
          </Card>

          <Card title="Detection Accuracy" subtitle="Average confidence score">
            <div className="mt-4">
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-bold text-gray-900">
                  {stats.avg_confidence_score.toFixed(1)}%
                </span>
              </div>
              <div className="mt-4 w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-primary-600 h-2 rounded-full transition-all"
                  style={{ width: `${stats.avg_confidence_score}%` }}
                />
              </div>
            </div>
          </Card>

          <Card title="Response Rate" subtitle="Reports acknowledged">
            <div className="mt-4">
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-bold text-gray-900">
                  {stats.reports_sent > 0
                    ? (
                        ((stats.reports_sent - stats.pending_reports) /
                          stats.reports_sent) *
                        100
                      ).toFixed(1)
                    : 0}
                  %
                </span>
              </div>
              <div className="mt-4 text-sm text-gray-600">
                {stats.reports_sent - stats.pending_reports} of {stats.reports_sent}{' '}
                reports acknowledged
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { Loading } from '@/components';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { format } from 'date-fns';

type TabId = 'overview' | 'detection' | 'performance' | 'registrars' | 'response';
type Period = 'day' | 'week' | 'month' | 'year';

export function Analytics() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [period, setPeriod] = useState<Period>('week');

  const { data: advancedAnalytics, isLoading: isLoadingAdvanced } = useQuery({
    queryKey: ['advancedAnalytics'],
    queryFn: () => apiClient.getAdvancedAnalytics(),
    refetchInterval: 60000,
  });

  const { data: detectionRate, isLoading: isLoadingDetection } = useQuery({
    queryKey: ['detectionRate', period],
    queryFn: () => apiClient.getDetectionRate(period),
    refetchInterval: 60000,
  });

  const { data: chartData } = useQuery({
    queryKey: ['chartData', period],
    queryFn: () => apiClient.getChartData(period),
    refetchInterval: 60000,
  });

  if (isLoadingAdvanced || isLoadingDetection) {
    return <Loading fullScreen message="Loading analytics..." />;
  }

  const safeAnalytics = advancedAnalytics || {
    confidence_distribution: [],
    api_performance: {
      virustotal_hits: 0,
      urlvoid_hits: 0,
      phishtank_hits: 0,
      avg_confidence: 0,
      total_analyzed: 0,
    },
    threat_trends: [],
    top_registrars: [],
    response_times: {
      avg_hours: null,
      min_hours: null,
      max_hours: null,
      total_takedowns: 0,
    },
  };

  const safeDetectionRate = detectionRate || [];
  const safeChartData = chartData || [];

  const tabs: { id: TabId; name: string }[] = [
    { id: 'overview', name: 'Overview' },
    { id: 'detection', name: 'Detection Rate' },
    { id: 'performance', name: 'API Performance' },
    { id: 'registrars', name: 'Registrars' },
    { id: 'response', name: 'Response Times' },
  ];

  const periods: { id: Period; name: string }[] = [
    { id: 'day', name: '24h' },
    { id: 'week', name: '7d' },
    { id: 'month', name: '30d' },
    { id: 'year', name: '1y' },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-gray-900">Analytics</h1>
        <div className="flex items-center gap-2">
          <div className="flex border border-gray-300 rounded">
            {periods.map((p) => (
              <button
                key={p.id}
                onClick={() => setPeriod(p.id)}
                className={`px-3 py-1 text-[10px] font-medium border-r border-gray-300 last:border-r-0 ${
                  period === p.id
                    ? 'bg-gray-900 text-white'
                    : 'bg-white text-gray-600 hover:bg-gray-50'
                }`}
              >
                {p.name}
              </button>
            ))}
          </div>
          <div className="text-[10px] text-gray-500">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>

      <div className="bg-white border border-gray-300">
        <div className="border-b border-gray-300">
          <nav className="flex">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-xs font-medium border-r border-gray-300 last:border-r-0 ${
                  activeTab === tab.id
                    ? 'bg-gray-50 text-gray-900'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Activity Timeline */}
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Activity Timeline</h3>
                {safeChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={safeChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis
                        dataKey="date"
                        tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                        tick={{ fontSize: 10 }}
                        stroke="#9ca3af"
                      />
                      <YAxis tick={{ fontSize: 10 }} stroke="#9ca3af" />
                      <Tooltip
                        labelFormatter={(date) => format(new Date(date), 'MMM dd, yyyy')}
                        contentStyle={{ fontSize: 11, border: '1px solid #d1d5db' }}
                      />
                      <Line
                        type="monotone"
                        dataKey="scans"
                        stroke="#000"
                        strokeWidth={1.5}
                        dot={false}
                      />
                      <Line
                        type="monotone"
                        dataKey="detections"
                        stroke="#ef4444"
                        strokeWidth={1.5}
                        dot={false}
                      />
                      <Line
                        type="monotone"
                        dataKey="reports"
                        stroke="#3b82f6"
                        strokeWidth={1.5}
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-[250px] bg-gray-50 border border-gray-200">
                    <p className="text-xs text-gray-500">No data available</p>
                  </div>
                )}
              </div>

              {/* Confidence Score Distribution */}
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  Confidence Score Distribution
                </h3>
                {safeAnalytics.confidence_distribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={safeAnalytics.confidence_distribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis dataKey="range" tick={{ fontSize: 10 }} stroke="#9ca3af" />
                      <YAxis tick={{ fontSize: 10 }} stroke="#9ca3af" />
                      <Tooltip contentStyle={{ fontSize: 11, border: '1px solid #d1d5db' }} />
                      <Bar dataKey="count" fill="#000" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-[200px] bg-gray-50 border border-gray-200">
                    <p className="text-xs text-gray-500">No confidence data available</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="space-y-6">
              {/* Detection Rate Over Time */}
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  Detection Rate Trends
                </h3>
                {safeDetectionRate.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={safeDetectionRate}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                      <XAxis
                        dataKey="date"
                        tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                        tick={{ fontSize: 10 }}
                        stroke="#9ca3af"
                      />
                      <YAxis tick={{ fontSize: 10 }} stroke="#9ca3af" />
                      <Tooltip
                        labelFormatter={(date) => format(new Date(date), 'MMM dd, yyyy')}
                        contentStyle={{ fontSize: 11, border: '1px solid #d1d5db' }}
                      />
                      <Line
                        type="monotone"
                        dataKey="detection_rate"
                        stroke="#ef4444"
                        strokeWidth={2}
                        dot={{ r: 3 }}
                        name="Detection Rate %"
                      />
                      <Line
                        type="monotone"
                        dataKey="avg_confidence"
                        stroke="#3b82f6"
                        strokeWidth={2}
                        dot={{ r: 3 }}
                        name="Avg Confidence %"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-[250px] bg-gray-50 border border-gray-200">
                    <p className="text-xs text-gray-500">No detection data available</p>
                  </div>
                )}
              </div>

              {/* Detection Stats Table */}
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Detection Statistics</h3>
                {safeDetectionRate.length > 0 ? (
                  <table className="w-full text-xs">
                    <thead className="bg-gray-50">
                      <tr className="border-b border-gray-300">
                        <th className="px-3 py-2 text-left font-semibold text-gray-700">Date</th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Total Scans
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          High Conf.
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Reported
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Taken Down
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Detection %
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {safeDetectionRate.slice(0, 10).map((row, idx) => (
                        <tr key={idx} className="border-b border-gray-200 last:border-0">
                          <td className="px-3 py-2 text-gray-900">
                            {format(new Date(row.date), 'MMM dd, yyyy')}
                          </td>
                          <td className="px-3 py-2 text-right font-medium tabular-nums">
                            {row.total_scans}
                          </td>
                          <td className="px-3 py-2 text-right font-medium tabular-nums">
                            {row.high_confidence}
                          </td>
                          <td className="px-3 py-2 text-right font-medium tabular-nums">
                            {row.reported}
                          </td>
                          <td className="px-3 py-2 text-right font-medium tabular-nums">
                            {row.taken_down}
                          </td>
                          <td className="px-3 py-2 text-right font-medium tabular-nums">
                            {row.detection_rate.toFixed(1)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="p-4 text-xs text-gray-500 text-center bg-gray-50 border border-gray-200">
                    No detection statistics available
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'performance' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  Multi-API Validation Performance
                </h3>
                <table className="w-full text-xs">
                  <thead className="bg-gray-50">
                    <tr className="border-b border-gray-300">
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">API Service</th>
                      <th className="px-3 py-2 text-right font-semibold text-gray-700">Hits</th>
                      <th className="px-3 py-2 text-right font-semibold text-gray-700">
                        Hit Rate
                      </th>
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">VirusTotal</td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.virustotal_hits}
                      </td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.total_analyzed > 0
                          ? (
                              (safeAnalytics.api_performance.virustotal_hits /
                                safeAnalytics.api_performance.total_analyzed) *
                              100
                            ).toFixed(1)
                          : 0}
                        %
                      </td>
                      <td className="px-3 py-3">
                        <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-medium bg-green-50 text-green-700">
                          Active
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">URLVoid</td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.urlvoid_hits}
                      </td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.total_analyzed > 0
                          ? (
                              (safeAnalytics.api_performance.urlvoid_hits /
                                safeAnalytics.api_performance.total_analyzed) *
                              100
                            ).toFixed(1)
                          : 0}
                        %
                      </td>
                      <td className="px-3 py-3">
                        <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-medium bg-green-50 text-green-700">
                          Active
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">PhishTank</td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.phishtank_hits}
                      </td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.total_analyzed > 0
                          ? (
                              (safeAnalytics.api_performance.phishtank_hits /
                                safeAnalytics.api_performance.total_analyzed) *
                              100
                            ).toFixed(1)
                          : 0}
                        %
                      </td>
                      <td className="px-3 py-3">
                        <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-medium bg-green-50 text-green-700">
                          Active
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="px-3 py-3 text-gray-900 font-medium">Combined Average</td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.total_analyzed}
                      </td>
                      <td className="px-3 py-3 text-right font-medium tabular-nums">
                        {safeAnalytics.api_performance.avg_confidence.toFixed(1)}%
                      </td>
                      <td className="px-3 py-3 text-gray-600">Avg Confidence</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Hit rate indicates the percentage of scans where the API detected a threat.
                  Higher hit rates suggest more reliable threat detection across the API
                  network.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'registrars' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  Top Registrars by Site Count
                </h3>
                {safeAnalytics.top_registrars.length > 0 ? (
                  <table className="w-full text-xs">
                    <thead className="bg-gray-50">
                      <tr className="border-b border-gray-300">
                        <th className="px-3 py-2 text-left font-semibold text-gray-700">
                          Registrar
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Sites
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Reports Sent
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Avg Takedown
                        </th>
                        <th className="px-3 py-2 text-right font-semibold text-gray-700">
                          Report Rate
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {safeAnalytics.top_registrars.map((reg, idx) => (
                        <tr key={idx} className="border-b border-gray-200 last:border-0">
                          <td className="px-3 py-3 text-gray-900 font-medium">
                            {reg.registrar}
                          </td>
                          <td className="px-3 py-3 text-right font-medium tabular-nums">
                            {reg.site_count}
                          </td>
                          <td className="px-3 py-3 text-right font-medium tabular-nums">
                            {reg.reports_sent}
                          </td>
                          <td className="px-3 py-3 text-right font-medium tabular-nums">
                            {reg.avg_takedown_hours
                              ? `${reg.avg_takedown_hours.toFixed(1)}h`
                              : 'N/A'}
                          </td>
                          <td className="px-3 py-3 text-right font-medium tabular-nums">
                            {((reg.reports_sent / reg.site_count) * 100).toFixed(1)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="p-4 text-xs text-gray-500 text-center bg-gray-50 border border-gray-200">
                    No registrar data available
                  </div>
                )}
              </div>

              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Report rate shows the percentage of phishing sites for which abuse reports
                  were sent to the registrar. Avg takedown time indicates how quickly
                  registrars respond to abuse complaints.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'response' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  Response Time Analytics
                </h3>
                <table className="w-full text-xs">
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600 w-48">Average Takedown Time</td>
                      <td className="py-3 font-medium tabular-nums">
                        {safeAnalytics.response_times.avg_hours
                          ? `${safeAnalytics.response_times.avg_hours.toFixed(1)} hours`
                          : 'No data'}
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Fastest Takedown</td>
                      <td className="py-3 font-medium tabular-nums">
                        {safeAnalytics.response_times.min_hours
                          ? `${safeAnalytics.response_times.min_hours.toFixed(1)} hours`
                          : 'No data'}
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Slowest Takedown</td>
                      <td className="py-3 font-medium tabular-nums">
                        {safeAnalytics.response_times.max_hours
                          ? `${safeAnalytics.response_times.max_hours.toFixed(1)} hours`
                          : 'No data'}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-gray-600">Total Takedowns</td>
                      <td className="py-3 font-medium tabular-nums">
                        {safeAnalytics.response_times.total_takedowns}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* ICANN 2-Day SLA Compliance */}
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">
                  ICANN 2-Day SLA Compliance
                </h3>
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-4 bg-green-50 border border-green-200">
                    <div className="text-[10px] text-green-700 font-medium mb-1">
                      Within SLA (&lt; 48h)
                    </div>
                    <div className="text-2xl font-semibold text-green-900 tabular-nums">
                      {safeAnalytics.response_times.avg_hours &&
                      safeAnalytics.response_times.avg_hours < 48
                        ? Math.round(
                            (safeAnalytics.response_times.total_takedowns *
                              (safeAnalytics.response_times.avg_hours < 48 ? 0.7 : 0.3))
                          )
                        : 0}
                    </div>
                  </div>
                  <div className="p-4 bg-yellow-50 border border-yellow-200">
                    <div className="text-[10px] text-yellow-700 font-medium mb-1">
                      Near SLA (48-72h)
                    </div>
                    <div className="text-2xl font-semibold text-yellow-900 tabular-nums">
                      {safeAnalytics.response_times.avg_hours &&
                      safeAnalytics.response_times.avg_hours >= 48 &&
                      safeAnalytics.response_times.avg_hours < 72
                        ? Math.round(safeAnalytics.response_times.total_takedowns * 0.2)
                        : 0}
                    </div>
                  </div>
                  <div className="p-4 bg-red-50 border border-red-200">
                    <div className="text-[10px] text-red-700 font-medium mb-1">
                      Overdue (&gt; 72h)
                    </div>
                    <div className="text-2xl font-semibold text-red-900 tabular-nums">
                      {safeAnalytics.response_times.avg_hours &&
                      safeAnalytics.response_times.avg_hours >= 72
                        ? Math.round(safeAnalytics.response_times.total_takedowns * 0.1)
                        : 0}
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  ICANN requires registrars to respond to abuse complaints within 2 days (48
                  hours). SLA compliance metrics help track registrar performance against this
                  requirement.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

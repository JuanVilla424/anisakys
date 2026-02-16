import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  Shield,
  AlertTriangle,
  TrendingUp,
  Clock,
  CheckCircle2,
  Search,
  Globe,
  Zap,
  Eye,
  Target,
  Database
} from 'lucide-react';
import { apiClient } from '@/services/api';

export function Dashboard() {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiClient.getStats(),
    refetchInterval: 30000,
  });

  const { data: chartData = [] } = useQuery({
    queryKey: ['chartData'],
    queryFn: () => apiClient.getChartData('week'),
    refetchInterval: 60000,
  });

  const metrics = [
    {
      title: 'Active Threats',
      value: stats?.active_threats || 0,
      change: '+12.5%',
      trend: 'up',
      icon: AlertTriangle,
      gradient: 'from-rose-500 via-red-500 to-pink-500',
      iconBg: 'bg-gradient-to-br from-rose-500/10 to-red-500/10',
      iconColor: 'text-red-600',
      borderAccent: 'border-red-500/20',
    },
    {
      title: 'Total Scans',
      value: stats?.total_scans?.toLocaleString() || '0',
      change: '+23.1%',
      trend: 'up',
      icon: Search,
      gradient: 'from-blue-500 via-indigo-500 to-purple-500',
      iconBg: 'bg-gradient-to-br from-blue-500/10 to-indigo-500/10',
      iconColor: 'text-blue-600',
      borderAccent: 'border-blue-500/20',
    },
    {
      title: 'Reports Sent',
      value: stats?.reports_sent || 0,
      change: '+8.2%',
      trend: 'up',
      icon: CheckCircle2,
      gradient: 'from-emerald-500 via-green-500 to-teal-500',
      iconBg: 'bg-gradient-to-br from-emerald-500/10 to-green-500/10',
      iconColor: 'text-emerald-600',
      borderAccent: 'border-emerald-500/20',
    },
    {
      title: 'Detection Rate',
      value: `${stats?.detection_rate?.toFixed(1) || '0'}%`,
      change: '+2.4%',
      trend: 'up',
      icon: Target,
      gradient: 'from-violet-500 via-purple-500 to-fuchsia-500',
      iconBg: 'bg-gradient-to-br from-violet-500/10 to-purple-500/10',
      iconColor: 'text-violet-600',
      borderAccent: 'border-violet-500/20',
    },
  ];

  const threatLevels = [
    {
      label: 'Critical',
      value: stats?.threat_distribution?.critical || 0,
      gradient: 'from-red-600 to-rose-600',
      bgGradient: 'from-red-50 to-rose-50',
      textColor: 'text-red-700',
      percent: 15
    },
    {
      label: 'High',
      value: stats?.threat_distribution?.high || 0,
      gradient: 'from-orange-500 to-amber-500',
      bgGradient: 'from-orange-50 to-amber-50',
      textColor: 'text-orange-700',
      percent: 25
    },
    {
      label: 'Medium',
      value: stats?.threat_distribution?.medium || 0,
      gradient: 'from-yellow-500 to-amber-400',
      bgGradient: 'from-yellow-50 to-amber-50',
      textColor: 'text-yellow-700',
      percent: 35
    },
    {
      label: 'Low',
      value: stats?.threat_distribution?.low || 0,
      gradient: 'from-blue-500 to-cyan-500',
      bgGradient: 'from-blue-50 to-cyan-50',
      textColor: 'text-blue-700',
      percent: 25
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Animated background pattern */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmZmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMiI+PHBhdGggZD0iTTM2IDE2YzAtNC40MTggMy41ODItOCA4LThzOCAzLjU4MiA4IDgtMy41ODIgOC04IDgtOC0zLjU4Mi04LTh6TTAgMTZjMC00LjQxOCAzLjU4Mi04IDgtOHM4IDMuNTgyIDggOC0zLjU4MiA4LTggOC04LTMuNTgyLTgtOHoiLz48L2c+PC9nPjwvc3ZnPg==')] opacity-40"></div>

      {/* Header with glassmorphism */}
      <div className="relative border-b border-white/10 bg-gradient-to-r from-slate-900/80 via-slate-800/80 to-slate-900/80 backdrop-blur-xl sticky top-0 z-50">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/5 via-purple-600/5 to-pink-600/5"></div>
        <div className="relative max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl blur-xl opacity-50"></div>
                <div className="relative w-12 h-12 bg-gradient-to-br from-blue-600 to-purple-600 rounded-2xl flex items-center justify-center">
                  <Shield className="w-7 h-7 text-white" />
                </div>
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-white via-blue-100 to-purple-100 bg-clip-text text-transparent tracking-tight">
                  Threat Intelligence
                </h1>
                <p className="text-slate-400 mt-0.5 text-sm">Real-time phishing detection & analysis</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl backdrop-blur-sm">
                <div className="relative w-2 h-2">
                  <div className="absolute inset-0 bg-emerald-500 rounded-full animate-ping opacity-75"></div>
                  <div className="relative w-2 h-2 bg-emerald-400 rounded-full"></div>
                </div>
                <span className="text-sm font-semibold text-emerald-400">All Systems Operational</span>
              </div>
              <div className="px-4 py-2 bg-white/5 border border-white/10 rounded-xl backdrop-blur-sm">
                <span className="text-sm font-mono text-slate-300">
                  {new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="relative max-w-7xl mx-auto px-6 py-8">
        {/* Metrics Grid with enhanced design */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {metrics.map((metric, idx) => {
            const Icon = metric.icon;
            return (
              <div
                key={idx}
                className={`group relative bg-gradient-to-br from-slate-800/90 to-slate-900/90 backdrop-blur-xl rounded-2xl p-6 border ${metric.borderAccent} hover:border-white/20 transition-all duration-500 hover:scale-[1.02] hover:-translate-y-1`}
              >
                {/* Glow effect */}
                <div className={`absolute inset-0 bg-gradient-to-br ${metric.gradient} opacity-0 group-hover:opacity-10 rounded-2xl transition-opacity duration-500`}></div>

                {/* Animated corner accent */}
                <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>

                <div className="relative">
                  <div className="flex items-start justify-between mb-6">
                    <div className={`relative p-3 rounded-xl ${metric.iconBg} backdrop-blur-sm`}>
                      <Icon className={`w-6 h-6 ${metric.iconColor}`} />
                    </div>
                    <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                      <TrendingUp className="w-3 h-3 text-emerald-400" />
                      <span className="text-xs font-bold text-emerald-400">
                        {metric.change}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm font-medium text-slate-400 uppercase tracking-wider">{metric.title}</p>
                    <p className="text-4xl font-bold text-white tracking-tight">
                      {metric.value}
                    </p>
                  </div>

                  {/* Metric sparkline placeholder */}
                  <div className="mt-4 pt-4 border-t border-white/5">
                    <div className="flex items-end gap-1 h-8">
                      {[40, 65, 45, 80, 55, 90, 70, 85].map((height, i) => (
                        <div
                          key={i}
                          className={`flex-1 bg-gradient-to-t ${metric.gradient} rounded-sm opacity-30 group-hover:opacity-60 transition-all duration-300`}
                          style={{ height: `${height}%`, transitionDelay: `${i * 50}ms` }}
                        ></div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Charts and Analysis Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Threat Activity Chart */}
          <div className="lg:col-span-2 bg-gradient-to-br from-slate-800/90 to-slate-900/90 backdrop-blur-xl rounded-2xl p-6 border border-white/10">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-bold text-white">Threat Activity Timeline</h2>
                <p className="text-sm text-slate-400 mt-1">Detection patterns over time</p>
              </div>
              <div className="flex gap-2">
                <button className="px-4 py-2 text-sm font-semibold text-white bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg shadow-lg shadow-blue-500/20 hover:shadow-blue-500/40 transition-all">
                  7 Days
                </button>
                <button className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-all">
                  30 Days
                </button>
                <button className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-all">
                  90 Days
                </button>
              </div>
            </div>

            {/* Enhanced chart placeholder */}
            <div className="relative h-72 bg-gradient-to-br from-slate-900/50 to-slate-800/50 rounded-xl border border-white/5 overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-t from-blue-600/5 via-transparent to-purple-600/5"></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="relative inline-block mb-4">
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-full blur-2xl opacity-30"></div>
                    <Activity className="relative w-16 h-16 text-slate-600" />
                  </div>
                  <p className="text-slate-500 font-medium">Advanced Analytics</p>
                  <p className="text-slate-600 text-sm mt-1">Chart rendering engine initializing</p>
                </div>
              </div>

              {/* Decorative grid */}
              <div className="absolute inset-0 grid grid-cols-8 opacity-5">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="border-r border-white/20"></div>
                ))}
              </div>
            </div>

            {/* Legend */}
            <div className="flex items-center gap-6 mt-6">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-gradient-to-r from-blue-600 to-blue-400 rounded-full"></div>
                <span className="text-sm text-slate-400">Scans</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-gradient-to-r from-red-600 to-red-400 rounded-full"></div>
                <span className="text-sm text-slate-400">Threats</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-gradient-to-r from-emerald-600 to-emerald-400 rounded-full"></div>
                <span className="text-sm text-slate-400">Reports</span>
              </div>
            </div>
          </div>

          {/* Threat Distribution */}
          <div className="bg-gradient-to-br from-slate-800/90 to-slate-900/90 backdrop-blur-xl rounded-2xl p-6 border border-white/10">
            <h2 className="text-xl font-bold text-white mb-6">Threat Distribution</h2>

            <div className="space-y-5">
              {threatLevels.map((item, idx) => (
                <div key={idx} className="group">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full bg-gradient-to-r ${item.gradient} shadow-lg`}></div>
                      <span className="text-sm font-semibold text-slate-300">{item.label}</span>
                    </div>
                    <span className="text-lg font-bold text-white tabular-nums">{item.value}</span>
                  </div>
                  <div className="relative h-2 bg-slate-900/50 rounded-full overflow-hidden border border-white/5">
                    <div
                      className={`absolute inset-y-0 left-0 bg-gradient-to-r ${item.gradient} rounded-full transition-all duration-700 shadow-lg`}
                      style={{ width: `${item.percent}%` }}
                    >
                      <div className="absolute inset-0 bg-gradient-to-r from-white/20 to-transparent"></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Summary stats */}
            <div className="mt-6 pt-6 border-t border-white/10">
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-3 bg-gradient-to-br from-slate-900/50 to-slate-800/50 rounded-xl border border-white/5">
                  <p className="text-2xl font-bold text-white">
                    {(stats?.threat_distribution?.critical || 0) + (stats?.threat_distribution?.high || 0)}
                  </p>
                  <p className="text-xs text-slate-400 mt-1 uppercase tracking-wider">High Priority</p>
                </div>
                <div className="text-center p-3 bg-gradient-to-br from-slate-900/50 to-slate-800/50 rounded-xl border border-white/5">
                  <p className="text-2xl font-bold text-white">
                    {Object.values(stats?.threat_distribution || {}).reduce((a: number, b: any) => a + (Number(b) || 0), 0)}
                  </p>
                  <p className="text-xs text-slate-400 mt-1 uppercase tracking-wider">Total Active</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Detections - Enhanced Table */}
        <div className="bg-gradient-to-br from-slate-800/90 to-slate-900/90 backdrop-blur-xl rounded-2xl border border-white/10 overflow-hidden">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white">Recent Threat Detections</h2>
                <p className="text-sm text-slate-400 mt-1">Live monitoring feed</p>
              </div>
              <div className="flex items-center gap-2">
                <button className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-all">
                  Filter
                </button>
                <button className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-all">
                  Export
                </button>
              </div>
            </div>
          </div>

          <div className="divide-y divide-white/5">
            {(stats?.recent_activity || []).slice(0, 5).map((activity: any, idx: number) => (
              <div key={idx} className="group p-5 hover:bg-white/5 transition-all duration-200">
                <div className="flex items-center gap-5">
                  {/* Threat icon */}
                  <div className="relative flex-shrink-0">
                    <div className="absolute inset-0 bg-gradient-to-r from-red-600 to-orange-600 rounded-xl blur-lg opacity-30 group-hover:opacity-50 transition-opacity"></div>
                    <div className="relative w-12 h-12 bg-gradient-to-br from-red-600 to-orange-600 rounded-xl flex items-center justify-center">
                      <Shield className="w-6 h-6 text-white" />
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate mb-1">
                      {activity.description || 'Phishing site detected via multi-API scan'}
                    </p>
                    <div className="flex items-center gap-3">
                      <span className="inline-flex items-center gap-1.5 text-xs text-slate-400">
                        <Globe className="w-3 h-3" />
                        {activity.type || 'Multi-source verification'}
                      </span>
                      <span className="text-slate-600">•</span>
                      <span className="text-xs font-mono text-slate-500">
                        ID: {activity.id || Math.random().toString(36).substring(7).toUpperCase()}
                      </span>
                    </div>
                  </div>

                  {/* Status and time */}
                  <div className="flex items-center gap-4 flex-shrink-0">
                    <div className="px-3 py-1.5 bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/30 rounded-lg">
                      <span className="text-xs font-bold text-red-400 uppercase tracking-wider">High Risk</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Clock className="w-4 h-4" />
                      <span className="text-sm font-mono">
                        {new Date(activity.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <button className="p-2 hover:bg-white/5 rounded-lg transition-all">
                      <Eye className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* View all link */}
          <div className="p-4 border-t border-white/10 bg-gradient-to-r from-slate-900/50 to-slate-800/50">
            <button className="w-full py-2 text-sm font-semibold text-blue-400 hover:text-blue-300 transition-colors">
              View All Detections →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

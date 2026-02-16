import { useState, useEffect } from 'react';
import apiClient from '@/services/api';
import type { PhishingSite } from '@/types';

export function Sites() {
  const [sites, setSites] = useState<PhishingSite[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [threatFilter, setThreatFilter] = useState<string>('');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [limit] = useState(50);

  useEffect(() => {
    fetchSites();
  }, [currentPage, statusFilter, threatFilter]);

  const fetchSites = async () => {
    setLoading(true);
    setError(null);

    try {
      const offset = (currentPage - 1) * limit;
      const params: any = { limit, offset };

      if (statusFilter) params.status = statusFilter;
      if (threatFilter) params.threat_level = threatFilter;

      const result = await apiClient.getPhishingSites(params);
      setSites(result.sites);
      setTotal(result.total);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load sites');
    } finally {
      setLoading(false);
    }
  };

  const handleRescan = async (id: number) => {
    // TODO: Implement rescan functionality
    alert(`Rescan functionality for site ${id} - To be implemented`);
  };

  const handleMarkTakenDown = async (id: number) => {
    try {
      await apiClient.updatePhishingSiteStatus(id, 'taken_down');
      fetchSites(); // Refresh list
    } catch (err: any) {
      alert(err.response?.data?.error || 'Failed to update status');
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'bg-red-50 text-red-700';
      case 'high':
        return 'bg-orange-50 text-orange-700';
      case 'medium':
        return 'bg-yellow-50 text-yellow-700';
      case 'low':
        return 'bg-blue-50 text-blue-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'confirmed':
        return 'bg-red-50 text-red-700';
      case 'reported':
        return 'bg-blue-50 text-blue-700';
      case 'pending':
        return 'bg-yellow-50 text-yellow-700';
      case 'false_positive':
        return 'bg-green-50 text-green-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="max-w-[1600px] mx-auto px-8 py-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-300 pb-4">
        <h1 className="text-lg font-semibold text-gray-900">Phishing Sites</h1>
        <p className="text-xs text-gray-600 mt-1">
          Detected phishing sites with threat analysis and reporting status
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Filters</h2>
        </div>
        <div className="p-6 grid grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1.5">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:border-gray-900"
            >
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="reported">Reported</option>
              <option value="confirmed">Confirmed</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1.5">
              Threat Level
            </label>
            <select
              value={threatFilter}
              onChange={(e) => {
                setThreatFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:border-gray-900"
            >
              <option value="">All Threat Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={() => {
                setStatusFilter('');
                setThreatFilter('');
                setCurrentPage(1);
              }}
              className="px-4 py-2 text-xs font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-white border border-gray-300 p-4">
          <div className="text-[10px] text-gray-500">Total Sites</div>
          <div className="text-lg font-semibold text-gray-900 tabular-nums">{total}</div>
        </div>
        <div className="bg-white border border-gray-300 p-4">
          <div className="text-[10px] text-gray-500">Current Page</div>
          <div className="text-lg font-semibold text-gray-900 tabular-nums">
            {currentPage} / {totalPages || 1}
          </div>
        </div>
        <div className="bg-white border border-gray-300 p-4">
          <div className="text-[10px] text-gray-500">Showing</div>
          <div className="text-lg font-semibold text-gray-900 tabular-nums">{sites.length}</div>
        </div>
        <div className="bg-white border border-gray-300 p-4">
          <div className="text-[10px] text-gray-500">Per Page</div>
          <div className="text-lg font-semibold text-gray-900 tabular-nums">{limit}</div>
        </div>
      </div>

      {/* Sites Table */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Detected Sites</h2>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin"></div>
            <p className="text-xs text-gray-600 mt-3">Loading sites...</p>
          </div>
        ) : error ? (
          <div className="p-6">
            <div className="px-3 py-2 bg-red-50 border border-red-200 text-xs text-red-700">
              {error}
            </div>
          </div>
        ) : sites.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-xs text-gray-600">No sites found matching the current filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 border-b border-gray-300">
                <tr>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">ID</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">URL</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Threat</th>
                  <th className="px-4 py-3 text-right text-[10px] font-medium text-gray-700">Confidence</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Abuse Email</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">First Seen</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-300">
                {sites.map((site) => (
                  <tr key={site.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-gray-900 tabular-nums">{site.id}</td>
                    <td className="px-4 py-3 text-gray-900 max-w-md">
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:text-blue-700 break-all"
                      >
                        {site.url}
                      </a>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-block px-2 py-0.5 text-[10px] font-medium ${getStatusColor(site.status)}`}>
                        {site.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-block px-2 py-0.5 text-[10px] font-medium ${getThreatLevelColor(site.threat_level)}`}>
                        {site.threat_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-gray-900 tabular-nums font-medium">
                      {site.confidence_score}%
                    </td>
                    <td className="px-4 py-3 text-gray-600">{site.abuse_email || '-'}</td>
                    <td className="px-4 py-3 text-gray-600">
                      {site.detected_at ? new Date(site.detected_at).toLocaleDateString() : '-'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRescan(site.id)}
                          className="text-[10px] text-blue-600 hover:text-blue-700 font-medium"
                        >
                          Rescan
                        </button>
                        {site.status !== 'false_positive' && (
                          <button
                            onClick={() => handleMarkTakenDown(site.id)}
                            className="text-[10px] text-green-600 hover:text-green-700 font-medium"
                          >
                            Mark Taken Down
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {!loading && sites.length > 0 && (
          <div className="px-6 py-4 border-t border-gray-300 flex items-center justify-between">
            <div className="text-xs text-gray-600">
              Showing {(currentPage - 1) * limit + 1} to{' '}
              {Math.min(currentPage * limit, total)} of {total} sites
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <div className="px-3 py-1.5 text-xs text-gray-900 tabular-nums">
                Page {currentPage} of {totalPages}
              </div>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

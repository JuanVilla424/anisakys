import { useState, useEffect } from 'react';
import apiClient from '@/services/api';
import type { ReportTracking } from '@/types';

export function Reports() {
  const [reports, setReports] = useState<ReportTracking[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [limit] = useState(50);

  // Modal for report details
  const [selectedReport, setSelectedReport] = useState<ReportTracking | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<string | null>(null);

  useEffect(() => {
    fetchReports();
  }, [currentPage, statusFilter]);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);

    try {
      const offset = (currentPage - 1) * limit;
      const params: any = { limit, offset };

      if (statusFilter) params.status = statusFilter;

      const result = await apiClient.getReports(params);
      setReports(result.reports);
      setTotal(result.total);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const handleViewReport = (report: ReportTracking) => {
    setSelectedReport(report);
    setShowModal(true);
  };

  const handleUpdateStatus = async (id: number, status: string) => {
    setUpdateStatus('updating');
    try {
      await apiClient.updateReportStatus(id, status);
      setUpdateStatus('success');
      setTimeout(() => {
        setUpdateStatus(null);
        setShowModal(false);
        fetchReports();
      }, 1000);
    } catch (err: any) {
      setUpdateStatus('error');
      setError(err.response?.data?.error || 'Failed to update status');
      setTimeout(() => setUpdateStatus(null), 3000);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'sent':
        return 'bg-blue-50 text-blue-700';
      case 'acknowledged':
        return 'bg-yellow-50 text-yellow-700';
      case 'resolved':
        return 'bg-green-50 text-green-700';
      case 'escalated':
        return 'bg-orange-50 text-orange-700';
      case 'overdue':
        return 'bg-red-50 text-red-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const getTimeRemaining = (deadline: string) => {
    const deadlineDate = new Date(deadline);
    const now = new Date();
    const diffMs = deadlineDate.getTime() - now.getTime();
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));

    if (diffHours < 0) {
      return { text: `${Math.abs(diffHours)}h overdue`, isOverdue: true };
    }
    if (diffHours < 24) {
      return { text: `${diffHours}h remaining`, isOverdue: false };
    }
    const days = Math.floor(diffHours / 24);
    return { text: `${days}d remaining`, isOverdue: false };
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="max-w-[1600px] mx-auto px-8 py-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-300 pb-4">
        <h1 className="text-lg font-semibold text-gray-900">Abuse Reports</h1>
        <p className="text-xs text-gray-600 mt-1">
          Track abuse reports and ICANN 2-day compliance deadlines
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Filters</h2>
        </div>
        <div className="p-6 grid grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1.5">
              Report Status
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
              <option value="sent">Sent</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
              <option value="escalated">Escalated</option>
              <option value="overdue">Overdue</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={() => {
                setStatusFilter('');
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
          <div className="text-[10px] text-gray-500">Total Reports</div>
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
          <div className="text-lg font-semibold text-gray-900 tabular-nums">{reports.length}</div>
        </div>
        <div className="bg-white border border-gray-300 p-4">
          <div className="text-[10px] text-gray-500">Per Page</div>
          <div className="text-lg font-semibold text-gray-900 tabular-nums">{limit}</div>
        </div>
      </div>

      {/* Reports Table */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Abuse Reports Tracking</h2>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="inline-block w-6 h-6 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin"></div>
            <p className="text-xs text-gray-600 mt-3">Loading reports...</p>
          </div>
        ) : error ? (
          <div className="p-6">
            <div className="px-3 py-2 bg-red-50 border border-red-200 text-xs text-red-700">
              {error}
            </div>
          </div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-xs text-gray-600">No reports found matching the current filters</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 border-b border-gray-300">
                <tr>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">ID</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">URL</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Abuse Email</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Reported At</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Deadline</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Time Remaining</th>
                  <th className="px-4 py-3 text-left text-[10px] font-medium text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-300">
                {reports.map((report) => {
                  const timeRemaining = getTimeRemaining(report.response_deadline);
                  return (
                    <tr key={report.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-gray-900 tabular-nums">{report.id}</td>
                      <td className="px-4 py-3 text-gray-900 max-w-md">
                        <a
                          href={report.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-700 break-all"
                        >
                          {report.url}
                        </a>
                      </td>
                      <td className="px-4 py-3 text-gray-600">{report.abuse_email}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-block px-2 py-0.5 text-[10px] font-medium ${getStatusColor(report.status)}`}>
                          {report.status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {new Date(report.reported_at).toLocaleDateString()} {new Date(report.reported_at).toLocaleTimeString()}
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {new Date(report.response_deadline).toLocaleDateString()} {new Date(report.response_deadline).toLocaleTimeString()}
                      </td>
                      <td className={`px-4 py-3 text-xs font-medium tabular-nums ${timeRemaining.isOverdue ? 'text-red-700' : 'text-gray-900'}`}>
                        {timeRemaining.text}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleViewReport(report)}
                          className="text-[10px] text-blue-600 hover:text-blue-700 font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {!loading && reports.length > 0 && (
          <div className="px-6 py-4 border-t border-gray-300 flex items-center justify-between">
            <div className="text-xs text-gray-600">
              Showing {(currentPage - 1) * limit + 1} to{' '}
              {Math.min(currentPage * limit, total)} of {total} reports
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

      {/* Report Details Modal */}
      {showModal && selectedReport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white border border-gray-300 max-w-3xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
              <h2 className="text-xs font-medium text-gray-900">Report Details</h2>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* URL */}
              <div>
                <div className="text-[10px] font-medium text-gray-700 mb-1">URL</div>
                <a
                  href={selectedReport.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:text-blue-700 break-all"
                >
                  {selectedReport.url}
                </a>
              </div>

              {/* Grid of Details */}
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Report ID</div>
                  <div className="text-xs text-gray-900 tabular-nums">#{selectedReport.id}</div>
                </div>
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Site ID</div>
                  <div className="text-xs text-gray-900 tabular-nums">#{selectedReport.site_id}</div>
                </div>
              </div>

              {/* Status */}
              <div>
                <div className="text-[10px] font-medium text-gray-700 mb-1">Status</div>
                <span className={`inline-block px-2 py-0.5 text-[10px] font-medium ${getStatusColor(selectedReport.status)}`}>
                  {selectedReport.status.toUpperCase()}
                </span>
              </div>

              {/* Abuse Contact */}
              <div>
                <div className="text-[10px] font-medium text-gray-700 mb-1">Abuse Contact Email</div>
                <div className="text-xs text-gray-900">{selectedReport.abuse_email}</div>
              </div>

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Reported At</div>
                  <div className="text-xs text-gray-900">
                    {new Date(selectedReport.reported_at).toLocaleString()}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Response Deadline (ICANN 2-Day SLA)</div>
                  <div className="text-xs text-gray-900">
                    {new Date(selectedReport.response_deadline).toLocaleString()}
                  </div>
                </div>
              </div>

              {selectedReport.response_received_at && (
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Response Received At</div>
                  <div className="text-xs text-gray-900">
                    {new Date(selectedReport.response_received_at).toLocaleString()}
                  </div>
                </div>
              )}

              {selectedReport.escalated_at && (
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Escalated At</div>
                  <div className="text-xs text-gray-900">
                    {new Date(selectedReport.escalated_at).toLocaleString()}
                  </div>
                </div>
              )}

              {/* Notes */}
              {selectedReport.notes && (
                <div>
                  <div className="text-[10px] font-medium text-gray-700 mb-1">Notes</div>
                  <div className="px-3 py-2 bg-gray-50 border border-gray-300 text-xs text-gray-900">
                    {selectedReport.notes}
                  </div>
                </div>
              )}

              {/* Update Status Messages */}
              {updateStatus === 'success' && (
                <div className="px-3 py-2 bg-green-50 border border-green-200 text-xs text-green-700">
                  Status updated successfully
                </div>
              )}
              {updateStatus === 'error' && error && (
                <div className="px-3 py-2 bg-red-50 border border-red-200 text-xs text-red-700">
                  {error}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-gray-300 bg-gray-50 flex items-center justify-between">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 text-xs font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50"
              >
                Close
              </button>
              <div className="flex gap-2">
                {selectedReport.status !== 'resolved' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedReport.id, 'resolved')}
                    disabled={updateStatus === 'updating'}
                    className="px-4 py-2 text-xs font-medium text-white bg-green-700 hover:bg-green-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
                  >
                    {updateStatus === 'updating' ? 'Updating...' : 'Mark Resolved'}
                  </button>
                )}
                {selectedReport.status !== 'escalated' && selectedReport.status !== 'resolved' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedReport.id, 'escalated')}
                    disabled={updateStatus === 'updating'}
                    className="px-4 py-2 text-xs font-medium text-white bg-red-700 hover:bg-red-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
                  >
                    {updateStatus === 'updating' ? 'Updating...' : 'Escalate'}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

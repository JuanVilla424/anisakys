import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileText,
  Send,
  Clock,
  CheckCircle,
  AlertCircle,
  ExternalLink,
  Filter,
} from 'lucide-react';
import { apiClient } from '@/services/api';
import {
  Card,
  Loading,
  StatusBadge,
  Button,
  Modal,
  Badge,
} from '@/components';
import type { ReportTracking } from '@/types';
import { format, differenceInHours } from 'date-fns';

export function Reports() {
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedReport, setSelectedReport] = useState<ReportTracking | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['reports', statusFilter],
    queryFn: () =>
      apiClient.getReports({
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({
      id,
      status,
      notes,
    }: {
      id: number;
      status: string;
      notes?: string;
    }) => apiClient.updateReportStatus(id, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setIsModalOpen(false);
    },
  });

  const handleViewReport = (report: ReportTracking) => {
    setSelectedReport(report);
    setIsModalOpen(true);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'sent':
        return <Send className="h-5 w-5 text-blue-500" />;
      case 'acknowledged':
        return <Clock className="h-5 w-5 text-yellow-500" />;
      case 'resolved':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'escalated':
      case 'overdue':
        return <AlertCircle className="h-5 w-5 text-red-500" />;
      default:
        return <FileText className="h-5 w-5 text-gray-500" />;
    }
  };

  const getTimeRemaining = (deadline: string) => {
    const hours = differenceInHours(new Date(deadline), new Date());
    if (hours < 0) {
      return { text: `${Math.abs(hours)}h overdue`, isOverdue: true };
    }
    if (hours < 24) {
      return { text: `${hours}h remaining`, isOverdue: false };
    }
    const days = Math.floor(hours / 24);
    return { text: `${days}d remaining`, isOverdue: false };
  };

  if (isLoading) {
    return <Loading fullScreen message="Loading reports..." />;
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="mt-2 text-gray-600">
            Track abuse reports and ICANN compliance
          </p>
        </div>
        <Button variant="primary">
          <Send className="h-4 w-4 mr-2" />
          New Report
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <div className="flex items-center gap-4">
          <Filter className="h-5 w-5 text-gray-400" />
          <div className="flex gap-2">
            {['all', 'sent', 'acknowledged', 'resolved', 'overdue', 'escalated'].map(
              (status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    statusFilter === status
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {status === 'all' ? 'All' : status.charAt(0).toUpperCase() + status.slice(1)}
                </button>
              )
            )}
          </div>
        </div>
      </Card>

      {/* Reports list */}
      {data && data.reports.length > 0 ? (
        <div className="space-y-4">
          {data.reports.map((report) => {
            const timeRemaining = getTimeRemaining(report.response_deadline);
            return (
              <Card key={report.id}>
                <div className="flex items-start gap-4">
                  <div className="mt-1">{getStatusIcon(report.status)}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <h3 className="text-lg font-semibold text-gray-900 truncate">
                          {report.url}
                        </h3>
                        <p className="mt-1 text-sm text-gray-600">
                          Report ID: #{report.id}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge status={report.status} />
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleViewReport(report)}
                        >
                          View Details
                        </Button>
                      </div>
                    </div>

                    <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
                      <div>
                        <p className="text-sm text-gray-600">Abuse Contact</p>
                        <p className="mt-1 text-sm font-medium text-gray-900">
                          {report.abuse_email}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-600">Reported At</p>
                        <p className="mt-1 text-sm font-medium text-gray-900">
                          {format(new Date(report.reported_at), 'MMM dd, yyyy HH:mm')}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-600">Response Deadline</p>
                        <p
                          className={`mt-1 text-sm font-medium ${
                            timeRemaining.isOverdue ? 'text-danger-600' : 'text-gray-900'
                          }`}
                        >
                          {format(new Date(report.response_deadline), 'MMM dd, yyyy HH:mm')}
                          <span className="ml-2 text-xs">({timeRemaining.text})</span>
                        </p>
                      </div>
                    </div>

                    {report.notes && (
                      <div className="mt-4 rounded-md bg-gray-50 p-3">
                        <p className="text-sm text-gray-700">{report.notes}</p>
                      </div>
                    )}
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <div className="text-center py-12">
            <FileText className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No reports found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {statusFilter === 'all'
                ? 'Get started by creating a new report.'
                : `No reports with status "${statusFilter}".`}
            </p>
          </div>
        </Card>
      )}

      {/* Report details modal */}
      {selectedReport && (
        <Modal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          title="Report Details"
          size="lg"
          footer={
            <div className="flex justify-between gap-4">
              <Button variant="secondary" onClick={() => setIsModalOpen(false)}>
                Close
              </Button>
              <div className="flex gap-2">
                {selectedReport.status !== 'resolved' && (
                  <Button
                    variant="success"
                    onClick={() =>
                      updateStatusMutation.mutate({
                        id: selectedReport.id,
                        status: 'resolved',
                      })
                    }
                    isLoading={updateStatusMutation.isPending}
                  >
                    Mark Resolved
                  </Button>
                )}
                {selectedReport.status !== 'escalated' && (
                  <Button
                    variant="danger"
                    onClick={() =>
                      updateStatusMutation.mutate({
                        id: selectedReport.id,
                        status: 'escalated',
                      })
                    }
                    isLoading={updateStatusMutation.isPending}
                  >
                    Escalate
                  </Button>
                )}
              </div>
            </div>
          }
        >
          <div className="space-y-6">
            <div>
              <h4 className="text-sm font-medium text-gray-700">URL</h4>
              <a
                href={selectedReport.url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-1 flex items-center gap-2 text-primary-600 hover:text-primary-700"
              >
                {selectedReport.url}
                <ExternalLink className="h-4 w-4" />
              </a>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-medium text-gray-700">Status</h4>
                <div className="mt-1">
                  <StatusBadge status={selectedReport.status} />
                </div>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-700">Site ID</h4>
                <p className="mt-1 text-sm text-gray-900">#{selectedReport.site_id}</p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-gray-700">Abuse Contact</h4>
              <p className="mt-1 text-sm text-gray-900">{selectedReport.abuse_email}</p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-medium text-gray-700">Reported At</h4>
                <p className="mt-1 text-sm text-gray-900">
                  {format(new Date(selectedReport.reported_at), 'MMM dd, yyyy HH:mm:ss')}
                </p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-700">Response Deadline</h4>
                <p className="mt-1 text-sm text-gray-900">
                  {format(
                    new Date(selectedReport.response_deadline),
                    'MMM dd, yyyy HH:mm:ss'
                  )}
                </p>
              </div>
            </div>

            {selectedReport.response_received_at && (
              <div>
                <h4 className="text-sm font-medium text-gray-700">Response Received</h4>
                <p className="mt-1 text-sm text-gray-900">
                  {format(
                    new Date(selectedReport.response_received_at),
                    'MMM dd, yyyy HH:mm:ss'
                  )}
                </p>
              </div>
            )}

            {selectedReport.escalated_at && (
              <div>
                <h4 className="text-sm font-medium text-gray-700">Escalated At</h4>
                <p className="mt-1 text-sm text-gray-900">
                  {format(new Date(selectedReport.escalated_at), 'MMM dd, yyyy HH:mm:ss')}
                </p>
              </div>
            )}

            {selectedReport.notes && (
              <div>
                <h4 className="text-sm font-medium text-gray-700">Notes</h4>
                <div className="mt-1 rounded-md bg-gray-50 p-3">
                  <p className="text-sm text-gray-700">{selectedReport.notes}</p>
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}

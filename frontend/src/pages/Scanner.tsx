import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  Search,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Shield,
  Info,
} from 'lucide-react';
import { apiClient } from '@/services/api';
import { Button, Card, Loading, ThreatLevelBadge, Badge } from '@/components';
import type { MultiAPIScanResult } from '@/types';
import { format } from 'date-fns';

export function Scanner() {
  const [url, setUrl] = useState('');
  const [scanResult, setScanResult] = useState<MultiAPIScanResult | null>(null);

  const scanMutation = useMutation({
    mutationFn: (url: string) => apiClient.scanUrl({ url, force_scan: true }),
    onSuccess: (data) => {
      setScanResult(data);
    },
  });

  const handleScan = () => {
    if (url.trim()) {
      scanMutation.mutate(url.trim());
    }
  };

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">URL Scanner</h1>
        <p className="mt-2 text-gray-600">
          Scan URLs using multiple threat intelligence APIs
        </p>
      </div>

      {/* Scan form */}
      <Card>
        <div className="flex gap-4">
          <div className="flex-1">
            <label htmlFor="url" className="sr-only">
              URL to scan
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-gray-400" />
              </div>
              <input
                id="url"
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                className="input pl-10"
                placeholder="Enter URL to scan (e.g., https://suspicious-site.com)"
                disabled={scanMutation.isPending}
              />
            </div>
          </div>
          <Button
            variant="primary"
            onClick={handleScan}
            isLoading={scanMutation.isPending}
            disabled={!url.trim()}
          >
            <Search className="h-4 w-4 mr-2" />
            Scan URL
          </Button>
        </div>

        {scanMutation.isError && (
          <div className="mt-4 rounded-md bg-danger-50 p-4">
            <div className="flex">
              <AlertTriangle className="h-5 w-5 text-danger-400" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-danger-800">Scan failed</h3>
                <p className="mt-2 text-sm text-danger-700">
                  {scanMutation.error?.message || 'An error occurred while scanning the URL'}
                </p>
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Loading state */}
      {scanMutation.isPending && (
        <Card>
          <Loading message="Scanning URL across multiple threat intelligence sources..." />
        </Card>
      )}

      {/* Scan results */}
      {scanResult && (
        <div className="space-y-6">
          {/* Overall result */}
          <Card>
            <div className="text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-gray-100">
                {scanResult.threat_level === 'safe' ? (
                  <CheckCircle className="h-10 w-10 text-success-600" />
                ) : (
                  <AlertTriangle className="h-10 w-10 text-danger-600" />
                )}
              </div>
              <h2 className="mt-4 text-2xl font-bold text-gray-900">
                Scan Complete
              </h2>
              <p className="mt-2 text-gray-600">{scanResult.url}</p>
              <div className="mt-4 flex items-center justify-center gap-4">
                <ThreatLevelBadge level={scanResult.threat_level} />
                <div className="text-3xl font-bold text-gray-900">
                  {scanResult.confidence_score}%
                </div>
                <span className="text-gray-600">Confidence</span>
              </div>
              <p className="mt-2 text-sm text-gray-500">
                Scanned at {format(new Date(scanResult.scan_time), 'MMM dd, yyyy HH:mm:ss')}
              </p>
            </div>
          </Card>

          {/* API Results */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* VirusTotal */}
            {scanResult.virustotal && (
              <Card title="VirusTotal" subtitle="70+ antivirus engines">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Detections:</span>
                    <span className="font-semibold text-gray-900">
                      {scanResult.virustotal.positives} / {scanResult.virustotal.total}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Scan Date:</span>
                    <span className="text-gray-900">
                      {format(new Date(scanResult.virustotal.scan_date), 'MMM dd, yyyy')}
                    </span>
                  </div>
                  <a
                    href={scanResult.virustotal.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-primary-600 hover:text-primary-700"
                  >
                    View full report <ExternalLink className="h-4 w-4" />
                  </a>
                </div>
              </Card>
            )}

            {/* URLVoid */}
            {scanResult.urlvoid && (
              <Card title="URLVoid" subtitle="30+ reputation sources">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Detections:</span>
                    <span className="font-semibold text-gray-900">
                      {scanResult.urlvoid.detections} / {scanResult.urlvoid.engines_count}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Reputation Score:</span>
                    <span className="text-gray-900">
                      {scanResult.urlvoid.reputation_score}/100
                    </span>
                  </div>
                </div>
              </Card>
            )}

            {/* PhishTank */}
            {scanResult.phishtank && (
              <Card title="PhishTank" subtitle="Community phishing database">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-600">In Database:</span>
                    {scanResult.phishtank.in_database ? (
                      <Badge variant="danger">Yes</Badge>
                    ) : (
                      <Badge variant="success">No</Badge>
                    )}
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Verified:</span>
                    {scanResult.phishtank.verified ? (
                      <Badge variant="danger">Yes</Badge>
                    ) : (
                      <Badge variant="info">No</Badge>
                    )}
                  </div>
                  {scanResult.phishtank.verification_time && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Verification Time:</span>
                      <span className="text-gray-900">
                        {format(
                          new Date(scanResult.phishtank.verification_time),
                          'MMM dd, yyyy'
                        )}
                      </span>
                    </div>
                  )}
                </div>
              </Card>
            )}

            {/* WHOIS */}
            {scanResult.whois && (
              <Card title="WHOIS Information" subtitle="Domain registration details">
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-600">Domain:</span>
                    <span className="text-gray-900">{scanResult.whois.domain}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Registrar:</span>
                    <span className="text-gray-900">{scanResult.whois.registrar}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600">Created:</span>
                    <span className="text-gray-900">
                      {format(new Date(scanResult.whois.creation_date), 'MMM dd, yyyy')}
                    </span>
                  </div>
                  {scanResult.whois.abuse_contact && (
                    <div className="flex justify-between">
                      <span className="text-gray-600">Abuse Contact:</span>
                      <span className="text-gray-900">
                        {scanResult.whois.abuse_contact}
                      </span>
                    </div>
                  )}
                </div>
              </Card>
            )}
          </div>

          {/* Recommendations */}
          {scanResult.recommendations && scanResult.recommendations.length > 0 && (
            <Card
              title="Recommendations"
              subtitle="Suggested actions based on scan results"
            >
              <div className="space-y-3">
                {scanResult.recommendations.map((recommendation, index) => (
                  <div key={index} className="flex gap-3">
                    <Info className="h-5 w-5 text-primary-600 flex-shrink-0 mt-0.5" />
                    <p className="text-gray-700">{recommendation}</p>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Screenshot */}
          {scanResult.screenshot_url && (
            <Card title="Screenshot" subtitle="Visual evidence">
              <img
                src={scanResult.screenshot_url}
                alt="Site screenshot"
                className="w-full rounded-lg border border-gray-200"
              />
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

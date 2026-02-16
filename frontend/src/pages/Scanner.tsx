import { useState } from 'react';
import apiClient from '@/services/api';
import type { MultiAPIScanResult } from '@/types';

export function Scanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MultiAPIScanResult | null>(null);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    // Basic URL validation
    try {
      new URL(url);
    } catch {
      setError('Invalid URL format. Please include http:// or https://');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setSaveStatus(null);

    try {
      const scanResult = await apiClient.scanUrl({ url: url.trim() });
      setResult(scanResult);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to scan URL. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveToSites = async () => {
    if (!result) return;

    setSaveStatus('saving');

    try {
      await apiClient.createReport({
        url: result.url,
        include_screenshot: true,
        include_evidence: true,
      });
      setSaveStatus('success');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (err: any) {
      setSaveStatus('error');
      setError(err.response?.data?.error || 'Failed to save site');
      setTimeout(() => setSaveStatus(null), 3000);
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
      case 'safe':
        return 'bg-green-50 text-green-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  return (
    <div className="max-w-[1600px] mx-auto px-8 py-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-300 pb-4">
        <h1 className="text-lg font-semibold text-gray-900">URL Scanner</h1>
        <p className="text-xs text-gray-600 mt-1">
          Multi-API phishing detection with VirusTotal, URLVoid, and PhishTank validation
        </p>
      </div>

      {/* Scan Form */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Scan URL</h2>
        </div>
        <div className="p-6">
          <form onSubmit={handleScan} className="space-y-4">
            <div>
              <label htmlFor="url" className="block text-xs font-medium text-gray-700 mb-1.5">
                Target URL
              </label>
              <input
                id="url"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://suspicious-domain.com"
                disabled={loading}
                className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:border-gray-900 disabled:bg-gray-50 disabled:text-gray-500"
              />
              <p className="text-[10px] text-gray-500 mt-1">
                Enter the full URL including http:// or https://
              </p>
            </div>

            {error && (
              <div className="px-3 py-2 bg-red-50 border border-red-200 text-xs text-red-700">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-white bg-gray-900 hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Scanning...' : 'Scan Now'}
            </button>
          </form>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="bg-white border border-gray-300 p-8">
          <div className="flex items-center justify-center space-x-3">
            <div className="w-4 h-4 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin"></div>
            <span className="text-xs text-gray-600">Running multi-API scan...</span>
          </div>
        </div>
      )}

      {/* Scan Results */}
      {result && !loading && (
        <div className="space-y-4">
          {/* Threat Summary */}
          <div className="bg-white border border-gray-300">
            <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
              <h2 className="text-xs font-medium text-gray-900">Threat Assessment</h2>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">URL Scanned</div>
                  <div className="text-xs text-gray-900 break-all">{result.url}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Confidence Score</div>
                  <div className="text-lg font-semibold text-gray-900 tabular-nums">
                    {result.confidence_score}%
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Threat Level</div>
                  <span className={`inline-block px-2 py-0.5 text-[10px] font-medium ${getThreatLevelColor(result.threat_level)}`}>
                    {result.threat_level.toUpperCase()}
                  </span>
                </div>
              </div>

              {result.recommendations && result.recommendations.length > 0 && (
                <div className="pt-4 border-t border-gray-300">
                  <div className="text-[10px] font-medium text-gray-700 mb-2">Recommendations</div>
                  <ul className="space-y-1">
                    {result.recommendations.map((rec, idx) => (
                      <li key={idx} className="text-xs text-gray-600 flex items-start">
                        <span className="mr-2">•</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="pt-4 border-t border-gray-300 flex gap-3">
                <button
                  onClick={handleSaveToSites}
                  disabled={saveStatus === 'saving'}
                  className="px-4 py-2 text-xs font-medium text-white bg-gray-900 hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  {saveStatus === 'saving' ? 'Saving...' : 'Save to Sites'}
                </button>
                {saveStatus === 'success' && (
                  <div className="px-3 py-2 bg-green-50 border border-green-200 text-xs text-green-700">
                    ✓ Site saved successfully
                  </div>
                )}
                {result.confidence_score >= 70 && (
                  <div className="text-xs text-gray-600 flex items-center">
                    High confidence - recommended for reporting
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* API Results */}
          <div className="grid grid-cols-2 gap-4">
            {/* VirusTotal */}
            {result.virustotal && (
              <div className="bg-white border border-gray-300">
                <div className="px-4 py-3 border-b border-gray-300 bg-gray-50">
                  <h3 className="text-xs font-medium text-gray-900">VirusTotal</h3>
                </div>
                <div className="p-4 space-y-2">
                  {result.virustotal.error ? (
                    <div className="text-xs text-red-600">{result.virustotal.error}</div>
                  ) : (
                    <>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-gray-500">Detections</span>
                        <span className="text-xs font-medium text-gray-900 tabular-nums">
                          {result.virustotal.positives} / {result.virustotal.total}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-gray-500">Detection Rate</span>
                        <span className="text-xs font-medium text-gray-900 tabular-nums">
                          {((result.virustotal.positives / result.virustotal.total) * 100).toFixed(1)}%
                        </span>
                      </div>
                      {result.virustotal.scan_date && (
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-gray-500">Scan Date</span>
                          <span className="text-xs text-gray-600">
                            {new Date(result.virustotal.scan_date).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                      {result.virustotal.permalink && (
                        <div className="pt-2 border-t border-gray-300">
                          <a
                            href={result.virustotal.permalink}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-blue-600 hover:text-blue-700"
                          >
                            View Full Report →
                          </a>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}

            {/* URLVoid */}
            {result.urlvoid && (
              <div className="bg-white border border-gray-300">
                <div className="px-4 py-3 border-b border-gray-300 bg-gray-50">
                  <h3 className="text-xs font-medium text-gray-900">URLVoid</h3>
                </div>
                <div className="p-4 space-y-2">
                  {result.urlvoid.error ? (
                    <div className="text-xs text-red-600">{result.urlvoid.error}</div>
                  ) : (
                    <>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-gray-500">Blacklist Detections</span>
                        <span className="text-xs font-medium text-gray-900 tabular-nums">
                          {result.urlvoid.detections} / {result.urlvoid.engines_count}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-gray-500">Detection Rate</span>
                        <span className="text-xs font-medium text-gray-900 tabular-nums">
                          {((result.urlvoid.detections / result.urlvoid.engines_count) * 100).toFixed(1)}%
                        </span>
                      </div>
                      {result.urlvoid.reputation_score !== undefined && (
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-gray-500">Reputation Score</span>
                          <span className="text-xs font-medium text-gray-900 tabular-nums">
                            {result.urlvoid.reputation_score}/100
                          </span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}

            {/* PhishTank */}
            {result.phishtank && (
              <div className="bg-white border border-gray-300">
                <div className="px-4 py-3 border-b border-gray-300 bg-gray-50">
                  <h3 className="text-xs font-medium text-gray-900">PhishTank</h3>
                </div>
                <div className="p-4 space-y-2">
                  {result.phishtank.error ? (
                    <div className="text-xs text-red-600">{result.phishtank.error}</div>
                  ) : (
                    <>
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-gray-500">In Database</span>
                        <span className={`px-2 py-0.5 text-[10px] font-medium ${result.phishtank.in_database ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700'}`}>
                          {result.phishtank.in_database ? 'YES' : 'NO'}
                        </span>
                      </div>
                      {result.phishtank.in_database && (
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-gray-500">Verified</span>
                          <span className={`px-2 py-0.5 text-[10px] font-medium ${result.phishtank.verified ? 'bg-red-50 text-red-700' : 'bg-yellow-50 text-yellow-700'}`}>
                            {result.phishtank.verified ? 'YES' : 'NO'}
                          </span>
                        </div>
                      )}
                      {result.phishtank.verification_time && (
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-gray-500">Verification Time</span>
                          <span className="text-xs text-gray-600">
                            {new Date(result.phishtank.verification_time).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}

            {/* WHOIS */}
            {result.whois && (
              <div className="bg-white border border-gray-300">
                <div className="px-4 py-3 border-b border-gray-300 bg-gray-50">
                  <h3 className="text-xs font-medium text-gray-900">WHOIS Information</h3>
                </div>
                <div className="p-4 space-y-2">
                  {result.whois.domain && (
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500">Domain</span>
                      <span className="text-xs text-gray-900">{result.whois.domain}</span>
                    </div>
                  )}
                  {result.whois.registrar && (
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500">Registrar</span>
                      <span className="text-xs text-gray-900">{result.whois.registrar}</span>
                    </div>
                  )}
                  {result.whois.creation_date && (
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500">Creation Date</span>
                      <span className="text-xs text-gray-600">
                        {new Date(result.whois.creation_date).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                  {result.whois.abuse_contact && (
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500">Abuse Contact</span>
                      <span className="text-xs text-gray-900">{result.whois.abuse_contact}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Screenshot */}
          {result.screenshot_url && (
            <div className="bg-white border border-gray-300">
              <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
                <h2 className="text-xs font-medium text-gray-900">Screenshot Evidence</h2>
              </div>
              <div className="p-6">
                <img
                  src={result.screenshot_url}
                  alt="Website screenshot"
                  className="w-full border border-gray-300"
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

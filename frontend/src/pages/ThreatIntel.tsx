import { useState } from 'react';
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

export function ThreatIntel() {
  const [activeTab, setActiveTab] = useState<string>('feeds');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // States for different modules
  const [feedData, setFeedData] = useState<any>(null);
  const [ctResults, setCtResults] = useState<any>(null);
  const [osintResults, setOsintResults] = useState<any>(null);
  const [comprehensiveScan, setComprehensiveScan] = useState<any>(null);

  // Form states
  const [brand, setBrand] = useState('');
  const [domain, setDomain] = useState('');
  const [url, setUrl] = useState('');

  const handleGetThreatFeeds = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('api_token');
      const response = await axios.get(
        `${API_BASE_URL}/threat-intel/threat-feeds`,
        {
          headers: { Authorization: `Bearer ${token}` },
          params: { max_per_feed: 500 }
        }
      );
      setFeedData(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch threat feeds');
    } finally {
      setLoading(false);
    }
  };

  const handleCertificateTransparency = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!brand.trim()) {
      setError('Brand name is required');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('api_token');
      const response = await axios.post(
        `${API_BASE_URL}/threat-intel/certificate-transparency`,
        {
          brand: brand.trim(),
          days_back: 30,
          legitimate_domains: []
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setCtResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to scan CT logs');
    } finally {
      setLoading(false);
    }
  };

  const handleOSINTAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('api_token');
      const response = await axios.post(
        `${API_BASE_URL}/threat-intel/osint-analysis`,
        { domain: domain.trim() },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setOsintResults(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to perform OSINT analysis');
    } finally {
      setLoading(false);
    }
  };

  const handleComprehensiveScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() && !domain.trim()) {
      setError('URL or Domain is required');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('api_token');
      const response = await axios.post(
        `${API_BASE_URL}/threat-intel/comprehensive-scan`,
        {
          url: url.trim() || undefined,
          domain: domain.trim() || undefined,
          brand: brand.trim() || undefined
        },
        {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 300000 // 5 minutes
        }
      );
      setComprehensiveScan(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to perform comprehensive scan');
    } finally {
      setLoading(false);
    }
  };

  const getThreatBadgeColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical_threat':
      case 'critical':
        return 'bg-red-50 text-red-700 border-red-300';
      case 'high_risk':
      case 'high':
        return 'bg-orange-50 text-orange-700 border-orange-300';
      case 'medium_risk':
      case 'medium':
        return 'bg-yellow-50 text-yellow-700 border-yellow-300';
      default:
        return 'bg-green-50 text-green-700 border-green-300';
    }
  };

  return (
    <div className="max-w-[1600px] mx-auto px-8 py-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-300 pb-4">
        <h1 className="text-lg font-semibold text-gray-900">
          Professional Threat Intelligence Platform
        </h1>
        <p className="text-xs text-gray-600 mt-1">
          Enterprise-grade threat detection: Certificate Transparency • Threat Feeds • OSINT • ML Classification • Social Media Monitoring
        </p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-300">
        <div className="flex space-x-6">
          {['feeds', 'certificate', 'osint', 'comprehensive'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`pb-3 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-gray-900 text-gray-900'
                  : 'border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300'
              }`}
            >
              {tab === 'feeds' && 'Threat Intelligence Feeds'}
              {tab === 'certificate' && 'Certificate Transparency'}
              {tab === 'osint' && 'OSINT Analysis'}
              {tab === 'comprehensive' && 'Comprehensive Scan'}
            </button>
          ))}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-300 p-4">
          <p className="text-xs text-red-700">{error}</p>
        </div>
      )}

      {/* Tab Content */}
      <div className="space-y-6">
        {/* THREAT FEEDS TAB */}
        {activeTab === 'feeds' && (
          <div className="space-y-4">
            <div className="bg-white border border-gray-300">
              <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
                <h2 className="text-xs font-medium text-gray-900">
                  Real-Time Threat Intelligence Feeds
                </h2>
                <p className="text-[10px] text-gray-600 mt-1">
                  OpenPhish • URLhaus • PhishTank - Live phishing & malware URLs
                </p>
              </div>
              <div className="p-6">
                <button
                  onClick={handleGetThreatFeeds}
                  disabled={loading}
                  className="px-4 py-2 bg-gray-900 text-white text-xs font-medium hover:bg-gray-800 disabled:bg-gray-400"
                >
                  {loading ? 'Loading Feeds...' : 'Fetch Active Threats'}
                </button>

                {feedData && (
                  <div className="mt-6 space-y-4">
                    <div className="grid grid-cols-4 gap-4">
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">Total Threats</div>
                        <div className="text-2xl font-bold text-gray-900 tabular-nums">
                          {feedData.statistics?.total_threats || 0}
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">OpenPhish</div>
                        <div className="text-2xl font-bold text-red-600 tabular-nums">
                          {feedData.statistics?.by_source?.openphish || 0}
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">URLhaus</div>
                        <div className="text-2xl font-bold text-orange-600 tabular-nums">
                          {feedData.statistics?.by_source?.urlhaus || 0}
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">PhishTank</div>
                        <div className="text-2xl font-bold text-blue-600 tabular-nums">
                          {feedData.statistics?.by_source?.phishtank || 0}
                        </div>
                      </div>
                    </div>

                    <div className="border border-gray-300">
                      <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                        <h3 className="text-xs font-medium text-gray-900">
                          Recent Threats ({feedData.threats?.slice(0, 50).length || 0} shown)
                        </h3>
                      </div>
                      <div className="max-h-96 overflow-y-auto">
                        <table className="w-full text-xs">
                          <thead className="bg-gray-50 sticky top-0">
                            <tr className="border-b border-gray-300">
                              <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">URL</th>
                              <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Source</th>
                              <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Type</th>
                              <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Confidence</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-300">
                            {feedData.threats?.slice(0, 50).map((threat: any, idx: number) => (
                              <tr key={idx} className="hover:bg-gray-50">
                                <td className="px-4 py-2">
                                  <div className="max-w-lg truncate font-mono text-[10px]">
                                    {threat.url}
                                  </div>
                                </td>
                                <td className="px-4 py-2">
                                  <span className="px-2 py-0.5 bg-blue-50 text-blue-700 text-[10px] border border-blue-300">
                                    {threat.source}
                                  </span>
                                </td>
                                <td className="px-4 py-2 text-[10px]">{threat.threat_type}</td>
                                <td className="px-4 py-2">
                                  <span className="tabular-nums font-medium">{threat.confidence}%</span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* CERTIFICATE TRANSPARENCY TAB */}
        {activeTab === 'certificate' && (
          <div className="space-y-4">
            <div className="bg-white border border-gray-300">
              <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
                <h2 className="text-xs font-medium text-gray-900">
                  Certificate Transparency Log Monitoring
                </h2>
                <p className="text-[10px] text-gray-600 mt-1">
                  Monitor CT logs for newly issued SSL certificates matching your brand
                </p>
              </div>
              <div className="p-6">
                <form onSubmit={handleCertificateTransparency} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-2">
                      Brand Name
                    </label>
                    <input
                      type="text"
                      value={brand}
                      onChange={(e) => setBrand(e.target.value)}
                      placeholder="e.g., paypal, facebook, bankofamerica"
                      className="w-full px-3 py-2 border border-gray-300 text-xs"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 bg-gray-900 text-white text-xs font-medium hover:bg-gray-800 disabled:bg-gray-400"
                  >
                    {loading ? 'Scanning CT Logs...' : 'Scan Certificate Transparency Logs'}
                  </button>
                </form>

                {ctResults && (
                  <div className="mt-6 space-y-4">
                    <div className="bg-gray-50 border border-gray-300 p-4">
                      <div className="grid grid-cols-3 gap-4">
                        <div>
                          <div className="text-[10px] text-gray-600 mb-1">Suspicious Certificates</div>
                          <div className="text-2xl font-bold text-red-600 tabular-nums">
                            {ctResults.certificates_found || 0}
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-gray-600 mb-1">Days Searched</div>
                          <div className="text-lg font-semibold text-gray-900 tabular-nums">
                            {ctResults.days_searched || 0}
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-gray-600 mb-1">Brand</div>
                          <div className="text-xs font-medium text-gray-900">
                            {ctResults.brand}
                          </div>
                        </div>
                      </div>
                    </div>

                    {ctResults.results && ctResults.results.length > 0 && (
                      <div className="border border-gray-300">
                        <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                          <h3 className="text-xs font-medium text-gray-900">
                            Suspicious Certificates Found
                          </h3>
                        </div>
                        <div className="max-h-96 overflow-y-auto">
                          <table className="w-full text-xs">
                            <thead className="bg-gray-50 sticky top-0">
                              <tr className="border-b border-gray-300">
                                <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Domain</th>
                                <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Suspicion Score</th>
                                <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Issuer</th>
                                <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Issued</th>
                                <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Actions</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-300">
                              {ctResults.results.map((cert: any, idx: number) => (
                                <tr key={idx} className={cert.suspicion_score >= 75 ? 'bg-red-50' : 'hover:bg-gray-50'}>
                                  <td className="px-4 py-2 font-mono text-[10px]">{cert.domain}</td>
                                  <td className="px-4 py-2">
                                    <div className={`inline-block px-3 py-1 border ${
                                      cert.suspicion_score >= 75 ? 'bg-red-50 text-red-700 border-red-300' :
                                      cert.suspicion_score >= 50 ? 'bg-orange-50 text-orange-700 border-orange-300' :
                                      'bg-yellow-50 text-yellow-700 border-yellow-300'
                                    }`}>
                                      <span className="font-bold tabular-nums">{cert.suspicion_score}%</span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-2 text-[10px]">{cert.issuer?.slice(0, 30) || 'Unknown'}</td>
                                  <td className="px-4 py-2 text-[10px]">{cert.not_before?.slice(0, 10)}</td>
                                  <td className="px-4 py-2">
                                    <a
                                      href={cert.crtsh_url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-blue-600 hover:text-blue-700 text-[10px]"
                                    >
                                      View Cert
                                    </a>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* OSINT TAB */}
        {activeTab === 'osint' && (
          <div className="space-y-4">
            <div className="bg-white border border-gray-300">
              <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
                <h2 className="text-xs font-medium text-gray-900">
                  OSINT (Open Source Intelligence) Analysis
                </h2>
                <p className="text-[10px] text-gray-600 mt-1">
                  WHOIS • DNS • IP Reputation • Shodan • Infrastructure Analysis
                </p>
              </div>
              <div className="p-6">
                <form onSubmit={handleOSINTAnalysis} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-2">
                      Domain to Analyze
                    </label>
                    <input
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="e.g., suspicious-domain.com"
                      className="w-full px-3 py-2 border border-gray-300 text-xs"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 bg-gray-900 text-white text-xs font-medium hover:bg-gray-800 disabled:bg-gray-400"
                  >
                    {loading ? 'Running OSINT Analysis...' : 'Run Comprehensive OSINT Analysis'}
                  </button>
                </form>

                {osintResults && (
                  <div className="mt-6 space-y-4">
                    <div className="grid grid-cols-4 gap-4">
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">Risk Score</div>
                        <div className={`text-2xl font-bold tabular-nums ${
                          osintResults.risk_score >= 70 ? 'text-red-600' :
                          osintResults.risk_score >= 50 ? 'text-orange-600' :
                          'text-green-600'
                        }`}>
                          {osintResults.risk_score}/100
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">Domain Age</div>
                        <div className="text-lg font-semibold text-gray-900 tabular-nums">
                          {osintResults.whois?.domain_age_days || '?'} days
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">IP Address</div>
                        <div className="text-xs font-mono text-gray-900">
                          {osintResults.ip || 'N/A'}
                        </div>
                      </div>
                      <div className="bg-gray-50 border border-gray-300 p-4">
                        <div className="text-[10px] text-gray-600 mb-1">Registrar</div>
                        <div className="text-[10px] text-gray-900">
                          {osintResults.whois?.registrar?.slice(0, 20) || 'Unknown'}
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      {/* WHOIS Info */}
                      <div className="border border-gray-300">
                        <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                          <h3 className="text-xs font-medium text-gray-900">WHOIS Information</h3>
                        </div>
                        <div className="p-4 space-y-2 text-[10px]">
                          <div><span className="text-gray-600">Creation Date:</span> <span className="font-medium">{osintResults.whois?.creation_date || 'Unknown'}</span></div>
                          <div><span className="text-gray-600">Expiration:</span> <span className="font-medium">{osintResults.whois?.expiration_date || 'Unknown'}</span></div>
                          <div><span className="text-gray-600">Country:</span> <span className="font-medium">{osintResults.whois?.country || 'Unknown'}</span></div>
                          {osintResults.whois?.newly_registered && (
                            <div className="mt-2 px-2 py-1 bg-red-50 text-red-700 border border-red-300">
                              ⚠️ NEWLY REGISTERED DOMAIN
                            </div>
                          )}
                        </div>
                      </div>

                      {/* DNS Info */}
                      <div className="border border-gray-300">
                        <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                          <h3 className="text-xs font-medium text-gray-900">DNS Records</h3>
                        </div>
                        <div className="p-4 space-y-2 text-[10px]">
                          <div><span className="text-gray-600">A Records:</span> <span className="font-mono">{osintResults.dns?.a_records?.join(', ') || 'None'}</span></div>
                          <div><span className="text-gray-600">MX Records:</span> <span className="font-mono text-[9px]">{osintResults.dns?.mx_records?.slice(0, 2).join(', ') || 'None'}</span></div>
                          <div><span className="text-gray-600">NS Records:</span> <span className="font-mono text-[9px]">{osintResults.dns?.ns_records?.slice(0, 2).join(', ') || 'None'}</span></div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* COMPREHENSIVE SCAN TAB */}
        {activeTab === 'comprehensive' && (
          <div className="space-y-4">
            <div className="bg-white border border-gray-300">
              <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
                <h2 className="text-xs font-medium text-gray-900">
                  Ultimate Comprehensive Threat Intelligence Scan
                </h2>
                <p className="text-[10px] text-gray-600 mt-1">
                  Combines ALL modules: Threat Feeds + CT + OSINT + ML + Social Media
                </p>
              </div>
              <div className="p-6">
                <form onSubmit={handleComprehensiveScan} className="space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-2">
                        URL (optional)
                      </label>
                      <input
                        type="text"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://suspicious-site.com"
                        className="w-full px-3 py-2 border border-gray-300 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-2">
                        Domain (optional)
                      </label>
                      <input
                        type="text"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        placeholder="suspicious-site.com"
                        className="w-full px-3 py-2 border border-gray-300 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-2">
                        Brand (optional)
                      </label>
                      <input
                        type="text"
                        value={brand}
                        onChange={(e) => setBrand(e.target.value)}
                        placeholder="paypal"
                        className="w-full px-3 py-2 border border-gray-300 text-xs"
                      />
                    </div>
                  </div>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-6 py-3 bg-red-600 text-white text-xs font-medium hover:bg-red-700 disabled:bg-gray-400"
                  >
                    {loading ? 'Running Comprehensive Scan...' : '🚀 Execute Comprehensive Scan (All Modules)'}
                  </button>
                  <p className="text-[10px] text-gray-600">
                    ⚠️ This scan runs all modules and may take 2-3 minutes
                  </p>
                </form>

                {comprehensiveScan && (
                  <div className="mt-6 space-y-4">
                    {/* Final Verdict */}
                    <div className={`border-2 p-6 ${getThreatBadgeColor(comprehensiveScan.final_verdict)}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-xs font-semibold mb-1">FINAL VERDICT</div>
                          <div className="text-2xl font-bold">{comprehensiveScan.final_verdict}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-[10px] mb-1">Threat Score</div>
                          <div className="text-4xl font-bold tabular-nums">
                            {comprehensiveScan.final_threat_score}/100
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Modules Executed */}
                    <div className="bg-gray-50 border border-gray-300 p-4">
                      <div className="text-xs font-medium text-gray-900 mb-2">
                        Modules Executed: {comprehensiveScan.modules_executed?.length || 0}
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {comprehensiveScan.modules_executed?.map((module: string) => (
                          <span
                            key={module}
                            className="px-2 py-1 bg-green-50 text-green-700 border border-green-300 text-[10px]"
                          >
                            ✓ {module.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Module Results */}
                    <div className="grid grid-cols-2 gap-4">
                      {comprehensiveScan.threat_feeds && (
                        <div className="border border-gray-300">
                          <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                            <h3 className="text-xs font-medium text-gray-900">Threat Feeds</h3>
                          </div>
                          <div className="p-4">
                            <div className={`text-lg font-bold ${
                              comprehensiveScan.threat_feeds.is_malicious ? 'text-red-600' : 'text-green-600'
                            }`}>
                              {comprehensiveScan.threat_feeds.is_malicious ? 'DETECTED IN FEEDS' : 'Not Found'}
                            </div>
                            <div className="text-[10px] text-gray-600 mt-1">
                              {comprehensiveScan.threat_feeds.detection_count} feed detections
                            </div>
                          </div>
                        </div>
                      )}

                      {comprehensiveScan.osint && (
                        <div className="border border-gray-300">
                          <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                            <h3 className="text-xs font-medium text-gray-900">OSINT Risk</h3>
                          </div>
                          <div className="p-4">
                            <div className={`text-lg font-bold ${
                              comprehensiveScan.osint.risk_score >= 70 ? 'text-red-600' :
                              comprehensiveScan.osint.risk_score >= 50 ? 'text-orange-600' :
                              'text-green-600'
                            }`}>
                              {comprehensiveScan.osint.risk_score}/100
                            </div>
                            <div className="text-[10px] text-gray-600 mt-1">
                              Domain age: {comprehensiveScan.osint.whois?.domain_age_days || '?'} days
                            </div>
                          </div>
                        </div>
                      )}

                      {comprehensiveScan.certificate_transparency && (
                        <div className="border border-gray-300">
                          <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                            <h3 className="text-xs font-medium text-gray-900">Certificate Transparency</h3>
                          </div>
                          <div className="p-4">
                            <div className={`text-lg font-bold ${
                              comprehensiveScan.certificate_transparency.suspicious_certs_found > 0 ? 'text-red-600' : 'text-green-600'
                            }`}>
                              {comprehensiveScan.certificate_transparency.suspicious_certs_found} Suspicious Certs
                            </div>
                          </div>
                        </div>
                      )}

                      {comprehensiveScan.ml_classification && (
                        <div className="border border-gray-300">
                          <div className="bg-gray-50 px-4 py-2 border-b border-gray-300">
                            <h3 className="text-xs font-medium text-gray-900">ML Classification</h3>
                          </div>
                          <div className="p-4">
                            <div className={`text-lg font-bold ${getThreatBadgeColor(comprehensiveScan.ml_classification.threat_level)}`}>
                              {comprehensiveScan.ml_classification.final_score}/100
                            </div>
                            <div className="text-[10px] text-gray-600 mt-1">
                              Threat Level: {comprehensiveScan.ml_classification.threat_level}
                            </div>
                            <div className="text-[10px] text-gray-600">
                              Confidence: {comprehensiveScan.ml_classification.confidence}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

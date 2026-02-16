import { useState } from 'react';
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

interface ScanResult {
  confidence_score: number;
  threat_level: string;
  virustotal?: any;
  urlvoid?: any;
  phishtank?: any;
}

interface ConfirmedPhishingSite {
  url: string;
  domain: string;
  source: string;
  is_ad?: boolean;
  title?: string;
  search_query?: string;
  similarity_score?: number;
  phishing_score?: number;
  scan_result: ScanResult;
}

interface ProfessionalResult {
  target_domain: string;
  target_brand: string;
  status: string;
  phases_completed: string[];
  typosquatting_results: {
    total_variants_generated: number;
    variants_checked: number;
    active_domains_found: number;
    inactive_domains_found: number;
  };
  search_engine_results?: {
    total_urls_found: number;
    by_source: Record<string, number>;
    ads_found: number;
    organic_found: number;
  };
  confirmed_phishing_sites: ConfirmedPhishingSite[];
  total_urls_scanned: number;
  total_confirmed_phishing: number;
  threat_assessment: {
    score: number;
    level: string;
    confirmed_phishing_count: number;
    typosquatting_active_count: number;
    search_urls_found: number;
    recommendation: string;
  };
}

export function Research() {
  const [domain, setDomain] = useState('');
  const [brand, setBrand] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProfessionalResult | null>(null);
  const [addingToSites, setAddingToSites] = useState<Set<string>>(new Set());

  const handleResearch = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!domain.trim()) {
      setError('Please enter a target domain');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = localStorage.getItem('api_token');
      const response = await axios.post(
        `${API_BASE_URL}/research/comprehensive`,
        {
          domain: domain.trim(),
          brand: brand.trim() || undefined,
          max_variants: 50,
          scan_search_engines: true,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: 600000, // 10 minutes for comprehensive research
        }
      );
      setResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to perform professional research');
    } finally {
      setLoading(false);
    }
  };

  const handleAddToSites = async (site: ConfirmedPhishingSite) => {
    const token = localStorage.getItem('api_token');
    setAddingToSites(prev => new Set(prev).add(site.url));

    try {
      await axios.post(
        `${API_BASE_URL}/report`,
        {
          url: site.url,
          source: `research_professional_${site.source}`,
          priority: site.scan_result.confidence_score >= 85 ? 'critical' : 'high',
          description: `CONFIRMED PHISHING via professional research - Source: ${site.source}, Confidence: ${site.scan_result.confidence_score}%`,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      setAddingToSites(prev => {
        const next = new Set(prev);
        next.delete(site.url);
        return next;
      });

      alert(`Added ${site.domain} to Sites`);
    } catch (err: any) {
      setAddingToSites(prev => {
        const next = new Set(prev);
        next.delete(site.url);
        return next;
      });
      alert(`Failed to add to sites: ${err.response?.data?.error || 'Unknown error'}`);
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-50 border-red-300 text-red-900';
      case 'high': return 'bg-orange-50 border-orange-300 text-orange-900';
      case 'medium': return 'bg-yellow-50 border-yellow-300 text-yellow-900';
      case 'low': return 'bg-blue-50 border-blue-300 text-blue-900';
      default: return 'bg-green-50 border-green-300 text-green-900';
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 90) return 'text-red-700 bg-red-50 border-red-300';
    if (score >= 80) return 'text-orange-700 bg-orange-50 border-orange-300';
    if (score >= 70) return 'text-yellow-700 bg-yellow-50 border-yellow-300';
    return 'text-blue-700 bg-blue-50 border-blue-300';
  };

  const getSourceLabel = (source: string) => {
    if (source === 'typosquatting') return 'Typosquatting';
    if (source.includes('google')) return source.includes('ad') ? 'Google Ad' : 'Google Organic';
    if (source.includes('bing')) return source.includes('ad') ? 'Bing Ad' : 'Bing Organic';
    if (source.includes('duckduckgo')) return 'DuckDuckGo';
    return source;
  };

  return (
    <div className="max-w-[1800px] mx-auto px-8 py-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-300 pb-4">
        <h1 className="text-lg font-semibold text-gray-900">Professional Phishing Research</h1>
        <p className="text-xs text-gray-600 mt-1">
          Automated comprehensive detection: Typosquatting + Search engines + Multi-API scanning + Confirmed verification
        </p>
      </div>

      {/* Research Form */}
      <div className="bg-white border border-gray-300">
        <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
          <h2 className="text-xs font-medium text-gray-900">Research Configuration</h2>
        </div>
        <div className="p-6">
          <form onSubmit={handleResearch} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="domain" className="block text-xs font-medium text-gray-700 mb-1.5">
                  Target Domain <span className="text-red-600">*</span>
                </label>
                <input
                  id="domain"
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="paypal.com"
                  disabled={loading}
                  className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:border-gray-900 disabled:bg-gray-50"
                />
                <p className="text-[10px] text-gray-500 mt-1">
                  The legitimate domain to protect - full automated research
                </p>
              </div>

              <div>
                <label htmlFor="brand" className="block text-xs font-medium text-gray-700 mb-1.5">
                  Brand Name <span className="text-gray-500">(optional)</span>
                </label>
                <input
                  id="brand"
                  type="text"
                  value={brand}
                  onChange={(e) => setBrand(e.target.value)}
                  placeholder="paypal"
                  disabled={loading}
                  className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:border-gray-900 disabled:bg-gray-50"
                />
                <p className="text-[10px] text-gray-500 mt-1">
                  Brand name for enhanced search targeting
                </p>
              </div>
            </div>

            {error && (
              <div className="px-3 py-2 bg-red-50 border border-red-200 text-xs text-red-700">
                {error}
              </div>
            )}

            <div className="bg-blue-50 border border-blue-200 p-4">
              <h3 className="text-xs font-semibold text-blue-900 mb-2">Professional Research Process</h3>
              <div className="text-xs text-blue-800 space-y-1">
                <p>• Phase 1: Generate and check typosquatting variants</p>
                <p>• Phase 2: Generate targeted search engine dorks</p>
                <p>• Phase 3: Scrape Google, Bing, DuckDuckGo for phishing sites and ads</p>
                <p>• Phase 4: Scan ALL found URLs with VirusTotal, URLVoid, PhishTank</p>
                <p>• Phase 5: Return ONLY confirmed phishing sites</p>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium text-white bg-gray-900 hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Running Professional Research...' : 'Start Professional Research'}
            </button>
          </form>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="bg-white border border-gray-300 p-8">
          <div className="space-y-4">
            <div className="flex items-center justify-center space-x-3">
              <div className="w-4 h-4 border-2 border-gray-300 border-t-gray-900 rounded-full animate-spin"></div>
              <span className="text-xs font-medium text-gray-900">
                Professional Research In Progress...
              </span>
            </div>
            <div className="text-[10px] text-gray-600 text-center space-y-1.5">
              <div>⚙️ This may take 3-5 minutes for comprehensive scanning</div>
              <div className="mt-3 space-y-1">
                <div>Phase 1: Generating typosquatting variants and checking DNS...</div>
                <div>Phase 2: Generating targeted search dorks...</div>
                <div>Phase 3: Scraping search engines (Google, Bing, DuckDuckGo)...</div>
                <div>Phase 4: Scanning all URLs with multi-API validation...</div>
                <div>Phase 5: Confirming phishing sites...</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-6">
          {/* Threat Assessment */}
          <div className={`border-2 p-6 ${getThreatColor(result.threat_assessment.level)}`}>
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <h3 className="text-sm font-semibold mb-2">
                  THREAT LEVEL: {result.threat_assessment.level.toUpperCase()}
                </h3>
                <p className="text-xs mb-3">
                  {result.threat_assessment.recommendation}
                </p>
              </div>
              <div className="text-right">
                <div className="text-[10px] mb-1">Threat Score</div>
                <div className="text-2xl font-bold tabular-nums">
                  {result.threat_assessment.score}/100
                </div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4 pt-4 border-t border-current border-opacity-20">
              <div>
                <div className="text-[10px] opacity-75 mb-1">Confirmed Phishing</div>
                <div className="text-lg font-semibold tabular-nums">
                  {result.total_confirmed_phishing}
                </div>
              </div>
              <div>
                <div className="text-[10px] opacity-75 mb-1">URLs Scanned</div>
                <div className="text-lg font-semibold tabular-nums">
                  {result.total_urls_scanned}
                </div>
              </div>
              <div>
                <div className="text-[10px] opacity-75 mb-1">Search URLs Found</div>
                <div className="text-lg font-semibold tabular-nums">
                  {result.search_engine_results?.total_urls_found || 0}
                </div>
              </div>
              <div>
                <div className="text-[10px] opacity-75 mb-1">Phases Completed</div>
                <div className="text-xs font-medium">
                  {result.phases_completed.length}/5
                </div>
              </div>
            </div>
          </div>

          {/* Research Summary */}
          <div className="bg-white border border-gray-300">
            <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
              <h2 className="text-xs font-medium text-gray-900">Research Summary</h2>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-5 gap-4">
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Typo Variants</div>
                  <div className="text-lg font-semibold text-gray-900 tabular-nums">
                    {result.typosquatting_results.variants_checked}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Active Typo Domains</div>
                  <div className="text-lg font-semibold text-red-600 tabular-nums">
                    {result.typosquatting_results.active_domains_found}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Search Ads Found</div>
                  <div className="text-lg font-semibold text-orange-600 tabular-nums">
                    {result.search_engine_results?.ads_found || 0}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Organic Results</div>
                  <div className="text-lg font-semibold text-blue-600 tabular-nums">
                    {result.search_engine_results?.organic_found || 0}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 mb-1">Confirmed Phishing</div>
                  <div className="text-lg font-semibold text-red-700 tabular-nums">
                    {result.total_confirmed_phishing}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Confirmed Phishing Sites */}
          <div className="bg-white border border-gray-300">
            <div className="px-6 py-4 border-b border-gray-300 bg-gray-50">
              <h2 className="text-xs font-medium text-gray-900">
                Confirmed Phishing Sites ({result.confirmed_phishing_sites.length})
              </h2>
              <p className="text-[10px] text-gray-600 mt-1">
                Only sites confirmed as phishing through multi-API scanning (confidence ≥ 70% or 3+ AV detections)
              </p>
            </div>

            {result.confirmed_phishing_sites.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 border-b border-gray-300">
                    <tr>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">URL</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Source</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Confidence</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Threat Level</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">VirusTotal</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">URLVoid</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">PhishTank</th>
                      <th className="px-4 py-2 text-left text-[10px] font-medium text-gray-700">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-300">
                    {result.confirmed_phishing_sites.map((site, idx) => (
                      <tr
                        key={idx}
                        className={`hover:bg-gray-50 ${
                          site.scan_result.confidence_score >= 90 ? 'bg-red-50' :
                          site.scan_result.confidence_score >= 80 ? 'bg-orange-50' : ''
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div className="max-w-md">
                            <a
                              href={site.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-600 hover:text-blue-700 break-all font-mono text-xs"
                            >
                              {site.url}
                            </a>
                            {site.title && (
                              <div className="text-[10px] text-gray-500 mt-0.5">
                                {site.title}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div>
                            <span className={`px-2 py-0.5 text-[10px] font-medium ${
                              site.is_ad ? 'bg-orange-50 text-orange-700 border border-orange-300' :
                              site.source === 'typosquatting' ? 'bg-red-50 text-red-700 border border-red-300' :
                              'bg-blue-50 text-blue-700 border border-blue-300'
                            }`}>
                              {getSourceLabel(site.source)}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className={`inline-block px-3 py-1 border-2 ${getConfidenceColor(site.scan_result.confidence_score)}`}>
                            <span className="text-base font-bold tabular-nums">
                              {site.scan_result.confidence_score}%
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 text-[10px] font-medium ${
                            site.scan_result.threat_level === 'critical' ? 'bg-red-50 text-red-700 border border-red-300' :
                            site.scan_result.threat_level === 'high' ? 'bg-orange-50 text-orange-700 border border-orange-300' :
                            'bg-yellow-50 text-yellow-700 border border-yellow-300'
                          }`}>
                            {site.scan_result.threat_level?.toUpperCase() || 'MEDIUM'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {site.scan_result.virustotal?.positives !== undefined ? (
                            <span className="tabular-nums font-medium">
                              {site.scan_result.virustotal.positives}/{site.scan_result.virustotal.total || 0}
                            </span>
                          ) : (
                            <span className="text-gray-400 text-[10px]">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {site.scan_result.urlvoid?.detections !== undefined ? (
                            <span className="tabular-nums font-medium">
                              {site.scan_result.urlvoid.detections} detections
                            </span>
                          ) : (
                            <span className="text-gray-400 text-[10px]">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {site.scan_result.phishtank?.in_database ? (
                            <span className="px-2 py-0.5 text-[10px] font-medium bg-red-50 text-red-700 border border-red-300">
                              IN DATABASE
                            </span>
                          ) : (
                            <span className="text-gray-400 text-[10px]">Not listed</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => handleAddToSites(site)}
                            disabled={addingToSites.has(site.url)}
                            className="px-3 py-1 text-xs font-medium text-white bg-gray-900 hover:bg-gray-800 disabled:bg-gray-400 disabled:cursor-not-allowed"
                          >
                            {addingToSites.has(site.url) ? 'Adding...' : 'Add to Sites'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-12 text-center">
                <div className="text-green-700 text-2xl mb-3">✓</div>
                <h3 className="text-sm font-medium text-green-900 mb-2">
                  No Confirmed Phishing Sites Detected
                </h3>
                <p className="text-xs text-green-700">
                  Scanned {result.total_urls_scanned} URLs across typosquatting and search engines.
                  No sites met the phishing confirmation threshold (confidence ≥ 70% or 3+ AV detections).
                </p>
              </div>
            )}
          </div>

          {/* Next Steps */}
          <div className="bg-blue-50 border border-blue-200 p-6">
            <h3 className="text-xs font-semibold text-blue-900 mb-3">Next Steps</h3>
            <div className="text-xs text-blue-800 space-y-2">
              <p><strong>1. Review Confirmed Sites:</strong> Examine all {result.total_confirmed_phishing} confirmed phishing sites above</p>
              <p><strong>2. Add to Sites:</strong> Click "Add to Sites" for each confirmed phishing site to track them</p>
              <p><strong>3. Generate Reports:</strong> Use Reports page to file abuse reports with registrars</p>
              <p><strong>4. Monitor:</strong> Set up recurring research to detect new phishing campaigns</p>
              <p><strong>5. Law Enforcement:</strong> If threat level is critical, consider reporting to authorities</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

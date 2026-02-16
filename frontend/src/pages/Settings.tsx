import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/services/api';
import { Loading } from '@/components';

type TabId = 'auth' | 'smtp' | 'api' | 'grinder' | 'auto-reporting' | 'icann';

export function Settings() {
  const [activeTab, setActiveTab] = useState<TabId>('auth');
  const [apiToken, setApiToken] = useState(() => localStorage.getItem('api_token') || '');
  const [tokenSaved, setTokenSaved] = useState(false);

  const { data: config, isLoading } = useQuery({
    queryKey: ['config'],
    queryFn: () => apiClient.getConfig(),
  });

  if (isLoading || !config) {
    return <Loading fullScreen message="Loading settings..." />;
  }

  const handleSaveToken = () => {
    localStorage.setItem('api_token', apiToken);
    setTokenSaved(true);
    setTimeout(() => setTokenSaved(false), 3000);
  };

  const handleClearToken = () => {
    localStorage.removeItem('api_token');
    setApiToken('');
    setTokenSaved(false);
  };

  const tabs: { id: TabId; name: string }[] = [
    { id: 'auth', name: '🔐 Authentication' },
    { id: 'smtp', name: 'SMTP' },
    { id: 'api', name: 'API Integrations' },
    { id: 'grinder', name: 'Grinder' },
    { id: 'auto-reporting', name: 'Auto-Reporting' },
    { id: 'icann', name: 'ICANN Compliance' },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-gray-900">Settings</h1>
        <div className="text-[10px] text-gray-500">
          Last updated: {new Date().toLocaleTimeString()}
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
          {activeTab === 'auth' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">API Authentication</h3>
                <p className="text-xs text-gray-600 mb-4">
                  Configure your Anisakys API token to authenticate requests from this interface.
                </p>

                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-2">
                      API Token
                    </label>
                    <input
                      type="password"
                      value={apiToken}
                      onChange={(e) => setApiToken(e.target.value)}
                      placeholder="Enter your API token"
                      className="w-full px-3 py-2 text-xs border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  <div className="flex gap-3">
                    <button
                      onClick={handleSaveToken}
                      disabled={!apiToken}
                      className={`px-4 py-2 text-xs font-medium text-white ${
                        apiToken
                          ? 'bg-blue-600 hover:bg-blue-700'
                          : 'bg-gray-400 cursor-not-allowed'
                      }`}
                    >
                      Save Token
                    </button>
                    <button
                      onClick={handleClearToken}
                      className="px-4 py-2 text-xs font-medium text-gray-700 bg-white border border-gray-300 hover:bg-gray-50"
                    >
                      Clear Token
                    </button>
                  </div>

                  {tokenSaved && (
                    <div className="p-3 bg-green-50 border border-green-200">
                      <p className="text-xs text-green-700">
                        ✅ API token saved successfully! You can now use the Research and other features.
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <div className="p-4 bg-blue-50 border border-blue-200">
                <h4 className="text-xs font-semibold text-blue-900 mb-2">📝 How to get your API token:</h4>
                <ol className="text-xs text-blue-800 space-y-1 list-decimal list-inside">
                  <li>Check your <code className="px-1 py-0.5 bg-blue-100 font-mono text-[10px]">.env</code> file</li>
                  <li>Look for <code className="px-1 py-0.5 bg-blue-100 font-mono text-[10px]">ANISAKYS_API_KEY</code></li>
                  <li>Copy the token value and paste it above</li>
                </ol>
              </div>

              <div className="p-4 bg-yellow-50 border border-yellow-200">
                <h4 className="text-xs font-semibold text-yellow-900 mb-2">⚠️ Security Notice:</h4>
                <p className="text-xs text-yellow-800">
                  Your API token is stored locally in your browser and never sent to any external service.
                  Keep your token secure and do not share it.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'smtp' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Email Server Configuration</h3>
                <table className="w-full text-xs">
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600 w-48">SMTP Host</td>
                      <td className="py-3 font-medium tabular-nums">{config.smtp.host}</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">SMTP Port</td>
                      <td className="py-3 font-medium tabular-nums">{config.smtp.port}</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Sender Email</td>
                      <td className="py-3 font-medium">{config.smtp.sender}</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">SMTP User</td>
                      <td className="py-3 font-medium">{config.smtp.user || 'Not configured'}</td>
                    </tr>
                    <tr>
                      <td className="py-3 text-gray-600">Authentication</td>
                      <td className="py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.smtp.auth_enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.smtp.auth_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Settings are configured via environment variables (.env file)
                </p>
              </div>
            </div>
          )}

          {activeTab === 'api' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Multi-API Validation System</h3>
                <table className="w-full text-xs">
                  <thead className="bg-gray-50">
                    <tr className="border-b border-gray-300">
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">Service</th>
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">Status</th>
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">Configuration</th>
                      <th className="px-3 py-2 text-left font-semibold text-gray-700">Coverage</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">VirusTotal</td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.virustotal.enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.api_integrations.virustotal.enabled ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.virustotal.configured
                            ? 'bg-blue-50 text-blue-700'
                            : 'bg-yellow-50 text-yellow-700'
                        }`}>
                          {config.api_integrations.virustotal.configured ? 'Configured' : 'Needs API Key'}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-gray-600">70+ AV engines</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">URLVoid</td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.urlvoid.enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.api_integrations.urlvoid.enabled ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.urlvoid.configured
                            ? 'bg-blue-50 text-blue-700'
                            : 'bg-yellow-50 text-yellow-700'
                        }`}>
                          {config.api_integrations.urlvoid.configured ? 'Configured' : 'Needs API Key'}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-gray-600">30+ blacklist sources</td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="px-3 py-3 text-gray-900 font-medium">PhishTank</td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.phishtank.enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.api_integrations.phishtank.enabled ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.phishtank.configured
                            ? 'bg-blue-50 text-blue-700'
                            : 'bg-yellow-50 text-yellow-700'
                        }`}>
                          {config.api_integrations.phishtank.configured ? 'Configured' : 'Needs API Key'}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-gray-600">Community database</td>
                    </tr>
                    <tr>
                      <td className="px-3 py-3 text-gray-900 font-medium">Auto-Scan</td>
                      <td className="px-3 py-3" colSpan={3}>
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.api_integrations.auto_scan_enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.api_integrations.auto_scan_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Configure API keys in .env file: VIRUSTOTAL_API_KEY, URLVOID_API_KEY, PHISHTANK_API_KEY
                </p>
              </div>
            </div>
          )}

          {activeTab === 'grinder' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Grinder Threat Intelligence</h3>
                <table className="w-full text-xs">
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600 w-48">Integration Status</td>
                      <td className="py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.grinder_integration.enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.grinder_integration.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">API URL</td>
                      <td className="py-3 font-medium">
                        {config.grinder_integration.api_url || 'Not configured'}
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">API Key</td>
                      <td className="py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.grinder_integration.configured
                            ? 'bg-blue-50 text-blue-700'
                            : 'bg-yellow-50 text-yellow-700'
                        }`}>
                          {config.grinder_integration.configured ? 'Configured' : 'Not configured'}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-gray-600">Features</td>
                      <td className="py-3 text-gray-600">
                        Automatic IP reporting, Threat correlation, Intelligence sharing
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Configure in .env file: GRINDER0X_API_URL, GRINDER0X_API_KEY
                </p>
              </div>
            </div>
          )}

          {activeTab === 'auto-reporting' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">Confidence Thresholds</h3>
                <table className="w-full text-xs">
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600 w-48">Auto-Report Threshold</td>
                      <td className="py-3">
                        <span className="font-medium tabular-nums">
                          {config.auto_reporting.auto_report_threshold}%
                        </span>
                        <span className="ml-2 text-gray-600">
                          (Automatic abuse report sent)
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Manual Review Threshold</td>
                      <td className="py-3">
                        <span className="font-medium tabular-nums">
                          {config.auto_reporting.manual_review_threshold}%
                        </span>
                        <span className="ml-2 text-gray-600">
                          (Requires analyst review)
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Analysis Delay</td>
                      <td className="py-3">
                        <span className="font-medium tabular-nums">
                          {config.auto_reporting.auto_analysis_delay}s
                        </span>
                        <span className="ml-2 text-gray-600">
                          (Wait time before multi-API scan)
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-gray-600" colSpan={2}>
                        <div className="space-y-2">
                          <p className="font-medium text-gray-900">Confidence Score Ranges:</p>
                          <div className="grid grid-cols-4 gap-2 mt-2">
                            <div className="p-2 bg-red-50 border border-red-200">
                              <div className="text-[10px] text-red-900 font-medium">85-100%</div>
                              <div className="text-[10px] text-red-700">Auto-report</div>
                            </div>
                            <div className="p-2 bg-yellow-50 border border-yellow-200">
                              <div className="text-[10px] text-yellow-900 font-medium">70-84%</div>
                              <div className="text-[10px] text-yellow-700">Manual review</div>
                            </div>
                            <div className="p-2 bg-blue-50 border border-blue-200">
                              <div className="text-[10px] text-blue-900 font-medium">50-69%</div>
                              <div className="text-[10px] text-blue-700">Monitor</div>
                            </div>
                            <div className="p-2 bg-gray-50 border border-gray-200">
                              <div className="text-[10px] text-gray-900 font-medium">0-49%</div>
                              <div className="text-[10px] text-gray-700">Low priority</div>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Configure in .env file: AUTO_REPORT_THRESHOLD_CONFIDENCE, MANUAL_REVIEW_THRESHOLD_CONFIDENCE, AUTO_ANALYSIS_DELAY_SECONDS
                </p>
              </div>
            </div>
          )}

          {activeTab === 'icann' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-xs font-semibold text-gray-900 mb-4">ICANN Compliance Features</h3>
                <table className="w-full text-xs">
                  <tbody>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600 w-48">Screenshots</td>
                      <td className="py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium ${
                          config.icann_compliance.screenshots_enabled
                            ? 'bg-green-50 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        }`}>
                          {config.icann_compliance.screenshots_enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Max Attachment Size</td>
                      <td className="py-3 font-medium tabular-nums">
                        {config.icann_compliance.max_attachment_size_mb} MB
                      </td>
                    </tr>
                    <tr className="border-b border-gray-200">
                      <td className="py-3 text-gray-600">Max Email Size</td>
                      <td className="py-3 font-medium tabular-nums">
                        {config.icann_compliance.max_email_size_mb} MB
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 text-gray-600" colSpan={2}>
                        <div className="space-y-2">
                          <p className="font-medium text-gray-900">Compliance Requirements:</p>
                          <ul className="mt-2 space-y-1 text-gray-600">
                            <li>• 2-day SLA tracking for registrar responses</li>
                            <li>• Automatic escalation management (Level 1, 2, 3)</li>
                            <li>• Evidence preservation (screenshots, WHOIS, DNS)</li>
                            <li>• Detailed abuse report documentation</li>
                            <li>• Response deadline monitoring</li>
                          </ul>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="p-3 bg-gray-50 border border-gray-200">
                <p className="text-[10px] text-gray-600">
                  Configure in .env file: SCREENSHOTS_DIR, MAX_ATTACHMENT_SIZE_MB, MAX_EMAIL_SIZE_MB
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white border border-gray-300 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-gray-900 mb-1">System Security</h3>
            <p className="text-[10px] text-gray-600">Global authentication settings</p>
          </div>
          <span className={`inline-flex px-2.5 py-1 rounded text-xs font-medium ${
            config.api_authentication_enabled
              ? 'bg-green-50 text-green-700'
              : 'bg-red-50 text-red-700'
          }`}>
            API Authentication: {config.api_authentication_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </div>
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings as SettingsIcon,
  Key,
  Mail,
  Database,
  Shield,
  Save,
  TestTube,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { apiClient } from '@/services/api';
import { Card, Button, Loading, Badge } from '@/components';
import type { Config } from '@/types';

export function Settings() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<
    'general' | 'apis' | 'smtp' | 'advanced'
  >('general');

  const { data: config, isLoading } = useQuery({
    queryKey: ['config'],
    queryFn: () => apiClient.getConfig(),
  });

  const [formData, setFormData] = useState<Partial<Config>>(config || {});

  const updateConfigMutation = useMutation({
    mutationFn: (data: Partial<Config>) => apiClient.updateConfig(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
    },
  });

  const testGrinderMutation = useMutation({
    mutationFn: () => apiClient.testGrinderConnection(),
  });

  const handleSave = () => {
    updateConfigMutation.mutate(formData);
  };

  if (isLoading || !config) {
    return <Loading fullScreen message="Loading settings..." />;
  }

  const tabs = [
    { id: 'general', name: 'General', icon: SettingsIcon },
    { id: 'apis', name: 'API Integrations', icon: Key },
    { id: 'smtp', name: 'Email/SMTP', icon: Mail },
    { id: 'advanced', name: 'Advanced', icon: Shield },
  ];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="mt-2 text-gray-600">
          Configure system settings and integrations
        </p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 border-b-2 px-1 py-4 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600'
                  : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      {/* General settings */}
      {activeTab === 'general' && (
        <div className="space-y-6">
          <Card title="Scan Configuration" subtitle="Configure domain scanning parameters">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Keywords
                </label>
                <input
                  type="text"
                  value={formData.keywords?.join(', ') || config.keywords.join(', ')}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      keywords: e.target.value.split(',').map((k) => k.trim()),
                    })
                  }
                  className="input mt-1"
                  placeholder="e.g., fb, facebook, face, book"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Comma-separated list of keywords to search for
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Target Domains (TLDs)
                </label>
                <input
                  type="text"
                  value={formData.domains?.join(', ') || config.domains.join(', ')}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      domains: e.target.value.split(',').map((d) => d.trim()),
                    })
                  }
                  className="input mt-1"
                  placeholder="e.g., .com, .net, .org"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Comma-separated list of TLDs to monitor
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Scan Interval (seconds)
                </label>
                <input
                  type="number"
                  value={formData.scan_interval || config.scan_interval}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      scan_interval: parseInt(e.target.value),
                    })
                  }
                  className="input mt-1"
                  min="60"
                />
                <p className="mt-1 text-sm text-gray-500">
                  How often to scan for new domains
                </p>
              </div>
            </div>
          </Card>

          <Card title="Thresholds" subtitle="Confidence score thresholds">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Auto-Report Threshold (%)
                </label>
                <input
                  type="number"
                  value={
                    formData.auto_report_threshold || config.auto_report_threshold
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      auto_report_threshold: parseInt(e.target.value),
                    })
                  }
                  className="input mt-1"
                  min="0"
                  max="100"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Automatically report threats above this confidence score
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Manual Review Threshold (%)
                </label>
                <input
                  type="number"
                  value={
                    formData.manual_review_threshold ||
                    config.manual_review_threshold
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      manual_review_threshold: parseInt(e.target.value),
                    })
                  }
                  className="input mt-1"
                  min="0"
                  max="100"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Flag for manual review between this and auto-report threshold
                </p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* API Integrations */}
      {activeTab === 'apis' && (
        <div className="space-y-6">
          <Card title="VirusTotal" subtitle="70+ antivirus engines">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={
                      formData.api_integrations?.virustotal?.enabled ??
                      config.api_integrations.virustotal.enabled
                    }
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        api_integrations: {
                          ...formData.api_integrations!,
                          virustotal: {
                            ...formData.api_integrations?.virustotal!,
                            enabled: e.target.checked,
                          },
                        },
                      })
                    }
                    className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm font-medium text-gray-700">Enabled</span>
                </label>
                <Badge
                  variant={
                    config.api_integrations.virustotal.enabled ? 'success' : 'info'
                  }
                >
                  {config.api_integrations.virustotal.enabled ? 'Active' : 'Inactive'}
                </Badge>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  API Key
                </label>
                <input
                  type="password"
                  value={
                    formData.api_integrations?.virustotal?.api_key ||
                    config.api_integrations.virustotal.api_key
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      api_integrations: {
                        ...formData.api_integrations!,
                        virustotal: {
                          ...formData.api_integrations?.virustotal!,
                          api_key: e.target.value,
                        },
                      },
                    })
                  }
                  className="input mt-1"
                  placeholder="Enter VirusTotal API key"
                />
              </div>
            </div>
          </Card>

          <Card title="URLVoid" subtitle="30+ reputation sources">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={
                      formData.api_integrations?.urlvoid?.enabled ??
                      config.api_integrations.urlvoid.enabled
                    }
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        api_integrations: {
                          ...formData.api_integrations!,
                          urlvoid: {
                            ...formData.api_integrations?.urlvoid!,
                            enabled: e.target.checked,
                          },
                        },
                      })
                    }
                    className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm font-medium text-gray-700">Enabled</span>
                </label>
                <Badge
                  variant={
                    config.api_integrations.urlvoid.enabled ? 'success' : 'info'
                  }
                >
                  {config.api_integrations.urlvoid.enabled ? 'Active' : 'Inactive'}
                </Badge>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  API Key
                </label>
                <input
                  type="password"
                  value={
                    formData.api_integrations?.urlvoid?.api_key ||
                    config.api_integrations.urlvoid.api_key
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      api_integrations: {
                        ...formData.api_integrations!,
                        urlvoid: {
                          ...formData.api_integrations?.urlvoid!,
                          api_key: e.target.value,
                        },
                      },
                    })
                  }
                  className="input mt-1"
                  placeholder="Enter URLVoid API key"
                />
              </div>
            </div>
          </Card>

          <Card title="Grinder0x" subtitle="Threat intelligence integration">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={
                      formData.api_integrations?.grinder?.enabled ??
                      config.api_integrations.grinder.enabled
                    }
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        api_integrations: {
                          ...formData.api_integrations!,
                          grinder: {
                            ...formData.api_integrations?.grinder!,
                            enabled: e.target.checked,
                          },
                        },
                      })
                    }
                    className="h-4 w-4 rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                  <span className="text-sm font-medium text-gray-700">Enabled</span>
                </label>
                <div className="flex gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => testGrinderMutation.mutate()}
                    isLoading={testGrinderMutation.isPending}
                  >
                    <TestTube className="h-4 w-4 mr-1" />
                    Test Connection
                  </Button>
                  <Badge
                    variant={
                      config.api_integrations.grinder.enabled ? 'success' : 'info'
                    }
                  >
                    {config.api_integrations.grinder.enabled ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
              </div>

              {testGrinderMutation.data && (
                <div
                  className={`rounded-md p-4 ${
                    testGrinderMutation.data.success
                      ? 'bg-success-50'
                      : 'bg-danger-50'
                  }`}
                >
                  <div className="flex">
                    {testGrinderMutation.data.success ? (
                      <CheckCircle className="h-5 w-5 text-success-400" />
                    ) : (
                      <XCircle className="h-5 w-5 text-danger-400" />
                    )}
                    <p
                      className={`ml-3 text-sm ${
                        testGrinderMutation.data.success
                          ? 'text-success-800'
                          : 'text-danger-800'
                      }`}
                    >
                      {testGrinderMutation.data.message}
                    </p>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Grinder URL
                </label>
                <input
                  type="url"
                  value={
                    formData.api_integrations?.grinder?.url ||
                    config.api_integrations.grinder.url
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      api_integrations: {
                        ...formData.api_integrations!,
                        grinder: {
                          ...formData.api_integrations?.grinder!,
                          url: e.target.value,
                        },
                      },
                    })
                  }
                  className="input mt-1"
                  placeholder="https://grinder.example.com:8080"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  API Key
                </label>
                <input
                  type="password"
                  value={
                    formData.api_integrations?.grinder?.api_key ||
                    config.api_integrations.grinder.api_key
                  }
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      api_integrations: {
                        ...formData.api_integrations!,
                        grinder: {
                          ...formData.api_integrations?.grinder!,
                          api_key: e.target.value,
                        },
                      },
                    })
                  }
                  className="input mt-1"
                  placeholder="Enter Grinder API key"
                />
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* SMTP Settings */}
      {activeTab === 'smtp' && (
        <Card title="SMTP Configuration" subtitle="Email server settings for abuse reports">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">
                SMTP Host
              </label>
              <input
                type="text"
                value={
                  formData.smtp_config?.host || config.smtp_config.host
                }
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    smtp_config: {
                      ...formData.smtp_config!,
                      host: e.target.value,
                    },
                  })
                }
                className="input mt-1"
                placeholder="smtp.example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                SMTP Port
              </label>
              <input
                type="number"
                value={
                  formData.smtp_config?.port || config.smtp_config.port
                }
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    smtp_config: {
                      ...formData.smtp_config!,
                      port: parseInt(e.target.value),
                    },
                  })
                }
                className="input mt-1"
                placeholder="587"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">
                Sender Email
              </label>
              <input
                type="email"
                value={
                  formData.smtp_config?.sender || config.smtp_config.sender
                }
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    smtp_config: {
                      ...formData.smtp_config!,
                      sender: e.target.value,
                    },
                  })
                }
                className="input mt-1"
                placeholder="abuse@example.com"
              />
            </div>
          </div>
        </Card>
      )}

      {/* Advanced Settings */}
      {activeTab === 'advanced' && (
        <div className="space-y-6">
          <Card title="Advanced Configuration" subtitle="Expert settings">
            <div className="rounded-md bg-yellow-50 p-4">
              <div className="flex">
                <Shield className="h-5 w-5 text-yellow-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800">
                    Caution: Advanced Settings
                  </h3>
                  <p className="mt-2 text-sm text-yellow-700">
                    Modifying these settings may affect system performance and
                    stability. Only proceed if you understand the implications.
                  </p>
                </div>
              </div>
            </div>
          </Card>

          <Card title="Database" subtitle="Database connection settings">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Database URL
                </label>
                <input
                  type="text"
                  className="input mt-1"
                  placeholder="postgresql://user:pass@host:port/db"
                  disabled
                />
                <p className="mt-1 text-sm text-gray-500">
                  Database configuration is managed via environment variables
                </p>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Save button */}
      <div className="flex justify-end gap-4">
        <Button variant="secondary" onClick={() => setFormData(config)}>
          Reset
        </Button>
        <Button
          variant="primary"
          onClick={handleSave}
          isLoading={updateConfigMutation.isPending}
        >
          <Save className="h-4 w-4 mr-2" />
          Save Settings
        </Button>
      </div>

      {updateConfigMutation.isSuccess && (
        <div className="rounded-md bg-success-50 p-4">
          <div className="flex">
            <CheckCircle className="h-5 w-5 text-success-400" />
            <p className="ml-3 text-sm text-success-800">
              Settings saved successfully!
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

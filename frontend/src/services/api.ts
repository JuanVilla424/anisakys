import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  PhishingSite,
  MultiAPIScanResult,
  ReportTracking,
  SystemStats,
  ScanRequest,
  ReportRequest,
  ApiError,
  Config,
} from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

class ApiClient {
  private client: AxiosInstance;
  private apiKey: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = this.getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ApiError>) => {
        if (error.response?.status === 401) {
          this.clearToken();
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  setToken(token: string) {
    this.apiKey = token;
    localStorage.setItem('api_token', token);
  }

  getToken(): string | null {
    if (!this.apiKey) {
      this.apiKey = localStorage.getItem('api_token');
    }
    return this.apiKey;
  }

  clearToken() {
    this.apiKey = null;
    localStorage.removeItem('api_token');
  }

  // Health check
  async healthCheck() {
    const response = await this.client.get('/health');
    return response.data;
  }

  // Authentication
  async login(apiKey: string) {
    this.setToken(apiKey);
    // Verify token by making a test request
    try {
      await this.getStats();
      return { success: true, apiKey };
    } catch (error) {
      this.clearToken();
      throw error;
    }
  }

  async logout() {
    this.clearToken();
  }

  // Statistics
  async getStats(): Promise<SystemStats> {
    const response = await this.client.get<SystemStats>('/stats');
    return response.data;
  }

  // URL Scanning
  async scanUrl(data: ScanRequest): Promise<MultiAPIScanResult> {
    const response = await this.client.post<MultiAPIScanResult>('/multi-scan', data);
    return response.data;
  }

  async getScanStatus(url: string): Promise<PhishingSite> {
    const response = await this.client.get<PhishingSite>(`/status/${encodeURIComponent(url)}`);
    return response.data;
  }

  // Phishing Sites
  async getPhishingSites(params?: {
    limit?: number;
    offset?: number;
    status?: string;
    threat_level?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<{ sites: PhishingSite[]; total: number }> {
    const response = await this.client.get('/sites', { params });
    return response.data;
  }

  async getPhishingSite(id: number): Promise<PhishingSite> {
    const response = await this.client.get<PhishingSite>(`/sites/${id}`);
    return response.data;
  }

  async updatePhishingSiteStatus(
    id: number,
    status: string
  ): Promise<PhishingSite> {
    const response = await this.client.patch<PhishingSite>(`/sites/${id}`, { status });
    return response.data;
  }

  // Reporting
  async createReport(data: ReportRequest): Promise<{ success: boolean; tracking_id: number }> {
    const response = await this.client.post('/report', data);
    return response.data;
  }

  async getReports(params?: {
    limit?: number;
    offset?: number;
    status?: string;
  }): Promise<{ reports: ReportTracking[]; total: number }> {
    const response = await this.client.get('/reports', { params });
    return response.data;
  }

  async getReport(id: number): Promise<ReportTracking> {
    const response = await this.client.get<ReportTracking>(`/reports/${id}`);
    return response.data;
  }

  async updateReportStatus(
    id: number,
    status: string,
    notes?: string
  ): Promise<ReportTracking> {
    const response = await this.client.patch<ReportTracking>(`/reports/${id}`, {
      status,
      notes,
    });
    return response.data;
  }

  // Analytics
  async getChartData(
    period: 'day' | 'week' | 'month' = 'week'
  ): Promise<Array<{ date: string; scans: number; detections: number; reports: number }>> {
    try {
      const response = await this.client.get('/analytics/chart', { params: { period } });
      return Array.isArray(response.data) ? response.data : [];
    } catch (error) {
      console.warn('Failed to fetch chart data:', error);
      return [];
    }
  }

  async getThreatMap(): Promise<
    Array<{
      ip: string;
      country: string;
      latitude: number;
      longitude: number;
      threat_count: number;
      last_seen: string;
    }>
  > {
    try {
      const response = await this.client.get('/analytics/threat-map');
      return Array.isArray(response.data) ? response.data : [];
    } catch (error) {
      console.warn('Failed to fetch threat map:', error);
      return [];
    }
  }

  // Configuration
  async getConfig(): Promise<Config> {
    const response = await this.client.get<Config>('/config');
    return response.data;
  }

  async updateConfig(config: Partial<Config>): Promise<Config> {
    const response = await this.client.put<Config>('/config', config);
    return response.data;
  }

  // Grinder Integration
  async testGrinderConnection(): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post('/grinder/test');
    return response.data;
  }
}

export const apiClient = new ApiClient();
export default apiClient;

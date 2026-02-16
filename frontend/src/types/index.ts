export interface User {
  id: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  apiKey: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  token: string | null;
}

export interface PhishingSite {
  id: number;
  url: string;
  detected_at: string;
  confidence_score: number;
  status: 'pending' | 'reported' | 'confirmed' | 'false_positive';
  threat_level: 'critical' | 'high' | 'medium' | 'low';
  abuse_email?: string;
  screenshot_path?: string;
  whois_data?: Record<string, unknown>;
  dns_records?: Record<string, unknown>;
}

export interface MultiAPIScanResult {
  url: string;
  scan_time: string;
  confidence_score: number;
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  virustotal?: {
    positives: number;
    total: number;
    scan_date: string;
    permalink: string;
    error?: string;
  };
  urlvoid?: {
    detections: number;
    engines_count: number;
    reputation_score: number;
    error?: string;
  };
  phishtank?: {
    in_database: boolean;
    verified: boolean;
    verification_time?: string;
    error?: string;
  };
  whois?: {
    domain: string;
    registrar: string;
    creation_date: string;
    abuse_contact?: string;
  };
  screenshot_url?: string;
  recommendations: string[];
}

export interface ReportTracking {
  id: number;
  site_id: number;
  url: string;
  abuse_email: string;
  reported_at: string;
  response_deadline: string;
  status: 'sent' | 'acknowledged' | 'resolved' | 'escalated' | 'overdue';
  response_received_at?: string;
  escalated_at?: string;
  notes?: string;
}

export interface SystemStats {
  total_scans: number;
  active_threats: number;
  reports_sent: number;
  pending_reports: number;
  overdue_reports: number;
  avg_confidence_score: number;
  scan_rate_24h: number;
  detection_rate: number;
  threat_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_keywords: Array<{ keyword: string; count: number }>;
  top_tlds: Array<{ tld: string; count: number }>;
  recent_activity: Array<{
    timestamp: string;
    type: 'scan' | 'detection' | 'report';
    description: string;
  }>;
}

export interface ThreatMapData {
  ip: string;
  country: string;
  latitude: number;
  longitude: number;
  threat_count: number;
  last_seen: string;
}

export interface ChartDataPoint {
  date: string;
  scans: number;
  detections: number;
  reports: number;
}

export interface ApiError {
  error: string;
  message: string;
  status_code: number;
}

export interface ScanRequest {
  url: string;
  force_scan?: boolean;
}

export interface ReportRequest {
  url: string;
  abuse_email?: string;
  cc_emails?: string[];
  include_screenshot?: boolean;
  include_evidence?: boolean;
}

export interface Config {
  smtp: {
    host: string;
    port: number;
    sender: string;
    user: string | null;
    auth_enabled: boolean;
  };
  api_integrations: {
    virustotal: {
      enabled: boolean;
      configured: boolean;
    };
    urlvoid: {
      enabled: boolean;
      configured: boolean;
    };
    phishtank: {
      enabled: boolean;
      configured: boolean;
    };
    auto_scan_enabled: boolean;
  };
  grinder_integration: {
    enabled: boolean;
    api_url: string | null;
    configured: boolean;
  };
  auto_reporting: {
    auto_report_threshold: number;
    manual_review_threshold: number;
    auto_analysis_delay: number;
  };
  icann_compliance: {
    screenshots_enabled: boolean;
    max_attachment_size_mb: number;
    max_email_size_mb: number;
  };
  api_authentication_enabled: boolean;
}

export interface AdvancedAnalytics {
  confidence_distribution: Array<{
    range: string;
    count: number;
  }>;
  api_performance: {
    virustotal_hits: number;
    urlvoid_hits: number;
    phishtank_hits: number;
    avg_confidence: number;
    total_analyzed: number;
  };
  threat_trends: Array<{
    date: string;
    threat_level: string;
    count: number;
  }>;
  top_registrars: Array<{
    registrar: string;
    site_count: number;
    reports_sent: number;
    avg_takedown_hours: number | null;
  }>;
  response_times: {
    avg_hours: number | null;
    min_hours: number | null;
    max_hours: number | null;
    total_takedowns: number;
  };
}

export interface DetectionRateData {
  date: string;
  total_scans: number;
  high_confidence: number;
  reported: number;
  taken_down: number;
  avg_confidence: number;
  detection_rate: number;
}

export type AnalysisMode = "text" | "image" | "url" | "voice";
export type RiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ResponseMeta {
  request_id: string;
  provider?: string | null;
  mode?: "demo" | "live" | null;
  persisted?: boolean | null;
}
export interface ScamAnalysis {
  id: string;
  input_type: AnalysisMode;
  risk_score: number;
  risk_level: RiskLevel;
  scam_type: string;
  confidence: number;
  red_flags: string[];
  explanation: string;
  recommendation: string[];
  created_at: string;
}

export interface AnalysisHistory {
  items: ScamAnalysis[];
  page: number;
  page_size: number;
  total: number;
}

export interface DashboardStats {
  total_analyses: number;
  high_risk_detected: number;
  critical_scams: number;
  most_common_scam_type: string | null;
}

export interface HealthStatus {
  status: string;
  service: string;
  database_configured: boolean;
  database: "not_configured" | "ready" | "unavailable";
  storage_configured: boolean;
  authentication_configured: boolean;
  rate_limiter: "disabled" | "ready" | "degraded";
}

export interface ApiSuccess<T> {
  success: true;
  data: T;
  meta: ResponseMeta;
}

export type AnalysisMode = "text" | "image" | "url" | "voice";
export type RiskLevel = "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SignalCategory = "urgency" | "impersonation" | "credential" | "financial" | "social_engineering" | "coercion" | "url" | "semantic";
export type SignalSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SignalSource = "rule" | "url" | "ai" | "cross_signal";

export interface RiskSignal {
  code: string;
  title: string;
  category: SignalCategory;
  severity: SignalSeverity;
  raw_score: number;
  contribution: number;
  confidence: number;
  source: SignalSource;
  evidence: string;
}

export interface EvidenceItem {
  id: string;
  title: string;
  category: SignalCategory;
  severity: SignalSeverity;
  explanation: string;
  source: string;
  score_contribution: number;
  artifact_reference?: string | null;
}

export interface UrlFinding {
  code: string;
  title: string;
  severity: SignalSeverity;
  explanation: string;
  score: number;
}

export interface UrlIntelligenceResult {
  normalized_url: string;
  hostname: string;
  registrable_domain?: string | null;
  scheme: string;
  port?: number | null;
  path: string;
  query_parameter_count: number;
  risk_score: number;
  risk_level: RiskLevel;
  findings: UrlFinding[];
}

export interface AttackChainNode {
  id: string;
  label: string;
  type: string;
  severity?: SignalSeverity | null;
}

export interface AttackChainEdge {
  source: string;
  target: string;
}

export interface AttackChain {
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
}

export type IncidentStage = "received_only" | "clicked_link" | "entered_information" | "shared_credential" | "sent_money";

export interface IncidentResponseGuidance {
  stage: IncidentStage;
  title: string;
  actions: string[];
}

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
  signals: RiskSignal[];
  evidence: EvidenceItem[];
  extracted_urls: string[];
  url_intelligence: UrlIntelligenceResult[];
  attack_chain: AttackChain;
  incident_response: IncidentResponseGuidance[];
  analysis_duration_ms?: number | null;
  ai_provider?: string | null;
  model_name?: string | null;
  scoring_version: string;
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

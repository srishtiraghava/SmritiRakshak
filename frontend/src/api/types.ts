export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type Decision = 'allow' | 'flag' | 'quarantine' | 'block';
export type MemorySource = 'conversation' | 'document' | 'tool' | 'system' | 'unknown';

export interface DetectorFinding {
  detector_name: string;
  category: string;
  severity: Severity;
  description: string;
  evidence: string;
  risk_points: number;
}

export interface MemoryProcessingResponse {
  memory_id: string | null;
  decision: Decision;
  reason: string;
  risk_score: number;
  risk_level: RiskLevel;
  findings: DetectorFinding[];
  flagged: boolean;
  timestamp: string;
}

export interface DashboardStatsResponse {
  total_processed: number;
  trusted_count: number;
  flagged_count: number;
  quarantined_count: number;
  blocked_count: number;
  threat_category_distribution: Record<string, number>;
  risk_score_distribution: Record<string, number>;
  recent_events: {
    id: string;
    decision: Decision;
    risk_score: number;
    user_id: string;
    source: string;
    timestamp: string;
    summary: string;
  }[];
  system_status: string;
  database_status: string;
}

export interface MemoryItemResponse {
  id: string;
  content: string | null;
  content_sha256: string | null;
  source: string;
  user_id: string;
  session_id: string | null;
  decision: Decision;
  risk_score: number;
  risk_level: RiskLevel;
  flagged: boolean;
  quarantine_reason: string | null;
  review_status: string | null;
  metadata_json: Record<string, any> | null;
  findings_json: DetectorFinding[];
  created_at: string;
}

export interface MemoryListResponse {
  total: number;
  page: number;
  page_size: number;
  items: MemoryItemResponse[];
}

export interface AuditEventItemResponse {
  id: string;
  event_type: string;
  decision: string;
  reason: string;
  risk_score: number;
  risk_level: string;
  user_id: string;
  session_id: string | null;
  source: string;
  sanitized_evidence: string | null;
  content_sha256: string;
  findings_json: DetectorFinding[];
  created_at: string;
}

export interface ThreatItemResponse {
  id: string;
  memory_id: string | null;
  detector_name: string;
  category: string;
  severity: string;
  description: string;
  evidence: string;
  risk_points: number;
  decision: string;
  user_id: string;
  timestamp: string;
}

export interface QuarantineReviewRequest {
  action: 'approve' | 'reject';
  reviewer_notes?: string;
}

export interface QuarantineReviewResponse {
  memory_id: string;
  action: 'approve' | 'reject';
  status: string;
  message: string;
  timestamp: string;
}

export interface SimulationRequest {
  content: string;
  source?: MemorySource;
  user_id?: string;
  session_id?: string;
  metadata?: Record<string, any>;
}

export interface SimulationResponse {
  decision: Decision;
  reason: string;
  risk_score: number;
  risk_level: RiskLevel;
  findings: DetectorFinding[];
  score_explanation: string;
  is_simulation: boolean;
  timestamp: string;
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  database: string;
}

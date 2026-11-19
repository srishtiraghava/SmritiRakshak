import {
  DashboardStatsResponse,
  HealthResponse,
  MemoryItemResponse,
  MemoryListResponse,
  MemoryProcessingResponse,
  AuditEventItemResponse,
  ThreatItemResponse,
  QuarantineReviewRequest,
  QuarantineReviewResponse,
  SimulationRequest,
  SimulationResponse,
} from './types';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api';

class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options?.headers || {}),
      },
    });

    if (!res.ok) {
      let errorDetail = res.statusText;
      try {
        const errorJson = await res.json();
        errorDetail = errorJson.detail || errorDetail;
      } catch {
        // use default statusText
      }
      throw new ApiError(res.status, res.statusText, errorDetail);
    }

    return (await res.json()) as T;
  } catch (err: any) {
    if (err instanceof ApiError) throw err;
    throw new Error(err.message || 'Network error connecting to SmritiRakshak API');
  }
}

export const api = {
  getHealth: () => request<HealthResponse>('/health'),

  getDashboardStats: () => request<DashboardStatsResponse>('/dashboard/stats'),

  listMemories: (params?: {
    decision?: string;
    user_id?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.decision) query.append('decision', params.decision);
    if (params?.user_id) query.append('user_id', params.user_id);
    if (params?.page) query.append('page', params.page.toString());
    if (params?.page_size) query.append('page_size', params.page_size.toString());
    const qs = query.toString();
    return request<MemoryListResponse>(`/memories${qs ? `?${qs}` : ''}`);
  },

  getMemoryDetail: (memoryId: string) =>
    request<MemoryItemResponse>(`/memories/${encodeURIComponent(memoryId)}`),

  submitMemory: (payload: {
    content: string;
    source: string;
    user_id: string;
    session_id?: string;
    metadata?: Record<string, any>;
  }) =>
    request<MemoryProcessingResponse>('/memories', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listAuditEvents: (userId?: string) => {
    const qs = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
    return request<AuditEventItemResponse[]>(`/audit-events${qs}`);
  },

  listThreats: (limit: number = 100) =>
    request<ThreatItemResponse[]>(`/threats?limit=${limit}`),

  reviewQuarantine: (memoryId: string, req: QuarantineReviewRequest) =>
    request<QuarantineReviewResponse>(
      `/quarantine/${encodeURIComponent(memoryId)}/review`,
      {
        method: 'POST',
        body: JSON.stringify(req),
      }
    ),

  simulateAttack: (req: SimulationRequest) =>
    request<SimulationResponse>('/simulate', {
      method: 'POST',
      body: JSON.stringify(req),
    }),
};

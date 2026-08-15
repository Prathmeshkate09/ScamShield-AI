import type { AnalysisHistory, ApiSuccess, DashboardStats, HealthStatus, ScamAnalysis } from "@/types/analysis";

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<ApiSuccess<T>> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...options,
    headers: {
      ...(options?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...options?.headers
    }
  });

  const payload = (await response.json().catch(() => null)) as ApiSuccess<T> | { error?: { message?: string } } | null;
  if (!response.ok || !payload || !("success" in payload) || !payload.success) {
    const message = payload && "error" in payload ? payload.error?.message : "The security service could not complete this request.";
    throw new ApiError(message ?? "The security service could not complete this request.", response.status);
  }
  return payload;
}

export const getHealth = () => request<HealthStatus>("/health");
export const getHistory = () => request<AnalysisHistory>("/api/v1/analyses?page=1&page_size=6");
export const getStats = () => request<DashboardStats>("/api/v1/analyses/stats");

export const analyzeText = (text: string) =>
  request<ScamAnalysis>("/api/v1/analyze/text", { method: "POST", body: JSON.stringify({ text }) });

export const analyzeUrl = (url: string) =>
  request<ScamAnalysis>("/api/v1/analyze/url", { method: "POST", body: JSON.stringify({ url }) });

export const analyzeVoice = (transcript: string) =>
  request<ScamAnalysis>("/api/v1/analyze/voice", { method: "POST", body: JSON.stringify({ transcript }) });

export const analyzeImage = (file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return request<ScamAnalysis>("/api/v1/analyze/image", { method: "POST", body: formData });
};

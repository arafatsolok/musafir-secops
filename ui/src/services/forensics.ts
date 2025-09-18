import { apiClient } from './api';
import { ApiResponse } from '../types/api';

export interface ForensicCase {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'completed' | 'on_hold';
  priority: 'low' | 'medium' | 'high' | 'critical';
  investigator: string;
  created: string;
  updated: string;
  evidence_count: number;
  artifacts_count: number;
}

export interface Evidence {
  id: string;
  case_id: string;
  name: string;
  type: 'disk_image' | 'memory_dump' | 'network_capture' | 'log_file' | 'registry' | 'file_system';
  size: string;
  hash: string;
  collected: string;
  source: string;
  status: 'processing' | 'analyzed' | 'corrupted';
}

export interface Artifact {
  id: string;
  evidence_id: string;
  type: string;
  description: string;
  timestamp: string;
  relevance: 'high' | 'medium' | 'low';
  tags: string[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  source: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface CreateForensicCaseRequest {
  name: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  investigator: string;
}

export interface CreateEvidenceRequest {
  case_id: string;
  name: string;
  type: 'disk_image' | 'memory_dump' | 'network_capture' | 'log_file' | 'registry' | 'file_system';
  source: string;
  hash?: string;
}

export class ForensicsService {
  // Forensic Cases
  async getCases(params?: {
    status?: string;
    priority?: string;
    investigator?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<ForensicCase[]>> {
    return apiClient.get<ForensicCase[]>('/forensics/cases', params);
  }

  async getCase(id: string): Promise<ApiResponse<ForensicCase>> {
    return apiClient.get<ForensicCase>(`/forensics/cases/${id}`);
  }

  async createCase(caseData: CreateForensicCaseRequest): Promise<ApiResponse<ForensicCase>> {
    return apiClient.post<ForensicCase>('/forensics/cases', caseData);
  }

  async updateCase(id: string, updates: Partial<ForensicCase>): Promise<ApiResponse<ForensicCase>> {
    return apiClient.put<ForensicCase>(`/forensics/cases/${id}`, updates);
  }

  async deleteCase(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/forensics/cases/${id}`);
  }

  // Evidence Management
  async getEvidence(caseId?: string): Promise<ApiResponse<Evidence[]>> {
    const params = caseId ? { case_id: caseId } : undefined;
    return apiClient.get<Evidence[]>('/forensics/evidence', params);
  }

  async getEvidenceItem(id: string): Promise<ApiResponse<Evidence>> {
    return apiClient.get<Evidence>(`/forensics/evidence/${id}`);
  }

  async createEvidence(evidenceData: CreateEvidenceRequest): Promise<ApiResponse<Evidence>> {
    return apiClient.post<Evidence>('/forensics/evidence', evidenceData);
  }

  async updateEvidence(id: string, updates: Partial<Evidence>): Promise<ApiResponse<Evidence>> {
    return apiClient.put<Evidence>(`/forensics/evidence/${id}`, updates);
  }

  async deleteEvidence(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/forensics/evidence/${id}`);
  }

  // Artifacts Management
  async getArtifacts(evidenceId?: string): Promise<ApiResponse<Artifact[]>> {
    const params = evidenceId ? { evidence_id: evidenceId } : undefined;
    return apiClient.get<Artifact[]>('/forensics/artifacts', params);
  }

  async getArtifact(id: string): Promise<ApiResponse<Artifact>> {
    return apiClient.get<Artifact>(`/forensics/artifacts/${id}`);
  }

  async createArtifact(artifactData: Omit<Artifact, 'id'>): Promise<ApiResponse<Artifact>> {
    return apiClient.post<Artifact>('/forensics/artifacts', artifactData);
  }

  async updateArtifact(id: string, updates: Partial<Artifact>): Promise<ApiResponse<Artifact>> {
    return apiClient.put<Artifact>(`/forensics/artifacts/${id}`, updates);
  }

  async deleteArtifact(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/forensics/artifacts/${id}`);
  }

  // Timeline Management
  async getTimeline(caseId: string): Promise<ApiResponse<TimelineEvent[]>> {
    return apiClient.get<TimelineEvent[]>(`/forensics/cases/${caseId}/timeline`);
  }

  async addTimelineEvent(caseId: string, eventData: Omit<TimelineEvent, 'id'>): Promise<ApiResponse<TimelineEvent>> {
    return apiClient.post<TimelineEvent>(`/forensics/cases/${caseId}/timeline`, eventData);
  }

  async updateTimelineEvent(caseId: string, eventId: string, updates: Partial<TimelineEvent>): Promise<ApiResponse<TimelineEvent>> {
    return apiClient.put<TimelineEvent>(`/forensics/cases/${caseId}/timeline/${eventId}`, updates);
  }

  async deleteTimelineEvent(caseId: string, eventId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/forensics/cases/${caseId}/timeline/${eventId}`);
  }

  // Analysis and Reports
  async startAnalysis(caseId: string, analysisType: string): Promise<ApiResponse<{ analysisId: string }>> {
    return apiClient.post<{ analysisId: string }>(`/forensics/cases/${caseId}/analysis`, { analysisType });
  }

  async getAnalysisStatus(caseId: string, analysisId: string): Promise<ApiResponse<{ status: string; progress: number }>> {
    return apiClient.get<{ status: string; progress: number }>(`/forensics/cases/${caseId}/analysis/${analysisId}`);
  }

  async generateReport(caseId: string, format: 'pdf' | 'json' | 'xml'): Promise<ApiResponse<{ reportUrl: string }>> {
    return apiClient.post<{ reportUrl: string }>(`/forensics/cases/${caseId}/report`, { format });
  }

  async exportEvidence(evidenceId: string, format: 'raw' | 'e01' | 'dd'): Promise<ApiResponse<{ exportUrl: string }>> {
    return apiClient.post<{ exportUrl: string }>(`/forensics/evidence/${evidenceId}/export`, { format });
  }
}

export const forensicsService = new ForensicsService();
import { apiClient } from './api';
import { Vulnerability, ApiResponse } from '../types/api';

export class VulnerabilityService {
  async getVulnerabilities(params?: {
    severity?: string;
    status?: string;
    cveId?: string;
    assetId?: string;
    page?: number;
    limit?: number;
    search?: string;
  }): Promise<ApiResponse<Vulnerability[]>> {
    return apiClient.get<Vulnerability[]>('/vulnerabilities', params);
  }

  async getVulnerability(id: string): Promise<ApiResponse<Vulnerability>> {
    return apiClient.get<Vulnerability>(`/vulnerabilities/${id}`);
  }

  async updateVulnerabilityStatus(id: string, status: string, reason?: string): Promise<ApiResponse<Vulnerability>> {
    return apiClient.put<Vulnerability>(`/vulnerabilities/${id}/status`, { status, reason });
  }

  async assignVulnerability(id: string, assignedTo: string): Promise<ApiResponse<Vulnerability>> {
    return apiClient.put<Vulnerability>(`/vulnerabilities/${id}/assign`, { assignedTo });
  }

  async getVulnerabilityDetails(cveId: string): Promise<ApiResponse<{
    cve: any;
    exploits: any[];
    patches: any[];
    references: string[];
  }>> {
    return apiClient.get(`/vulnerabilities/cve/${cveId}`);
  }

  async scanForVulnerabilities(assetIds?: string[]): Promise<ApiResponse<{ scanId: string }>> {
    return apiClient.post('/vulnerabilities/scan', { assetIds });
  }

  async getVulnerabilityStats(): Promise<ApiResponse<{
    total: number;
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
    trends: Array<{ date: string; count: number }>;
    topCves: Array<{ cveId: string; count: number; severity: string }>;
  }>> {
    return apiClient.get('/vulnerabilities/stats');
  }

  async getPatchManagement(): Promise<ApiResponse<{
    availablePatches: number;
    criticalPatches: number;
    patchingSchedule: Array<{
      date: string;
      patches: number;
      criticality: string;
    }>;
  }>> {
    return apiClient.get('/vulnerabilities/patches');
  }

  async createRemediationPlan(vulnerabilityIds: string[], priority: string): Promise<ApiResponse<{
    planId: string;
    estimatedTime: string;
    steps: Array<{
      step: number;
      description: string;
      estimatedTime: string;
    }>;
  }>> {
    return apiClient.post('/vulnerabilities/remediation-plan', { vulnerabilityIds, priority });
  }

  async bulkUpdateVulnerabilities(vulnerabilityIds: string[], updates: {
    status?: string;
    assignedTo?: string;
    priority?: string;
  }): Promise<ApiResponse<void>> {
    return apiClient.put('/vulnerabilities/bulk-update', { vulnerabilityIds, updates });
  }
}

export const vulnerabilityService = new VulnerabilityService();
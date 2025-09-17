import { apiClient } from './api';
import { Alert, ApiResponse } from '../types/api';

export class AlertService {
  async getAlerts(params?: {
    status?: string;
    severity?: string;
    category?: string;
    source?: string;
    page?: number;
    limit?: number;
    startTime?: string;
    endTime?: string;
  }): Promise<ApiResponse<Alert[]>> {
    return apiClient.get<Alert[]>('/alerts', params);
  }

  async getAlert(id: string): Promise<ApiResponse<Alert>> {
    return apiClient.get<Alert>(`/alerts/${id}`);
  }

  async updateAlertStatus(id: string, status: string): Promise<ApiResponse<Alert>> {
    return apiClient.put<Alert>(`/alerts/${id}/status`, { status });
  }

  async acknowledgeAlert(id: string): Promise<ApiResponse<Alert>> {
    return apiClient.put<Alert>(`/alerts/${id}/acknowledge`);
  }

  async escalateAlert(id: string, reason?: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${id}/escalate`, { reason });
  }

  async createIncidentFromAlert(alertId: string, incidentData: {
    title: string;
    description: string;
    severity: string;
  }): Promise<ApiResponse<{ incidentId: string }>> {
    return apiClient.post(`/alerts/${alertId}/create-incident`, incidentData);
  }

  async getAlertStats(): Promise<ApiResponse<{
    total: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    trends: Array<{ date: string; count: number }>;
  }>> {
    return apiClient.get('/alerts/stats');
  }

  async getRecentAlerts(limit: number = 10): Promise<ApiResponse<Alert[]>> {
    return apiClient.get<Alert[]>('/alerts/recent', { limit });
  }

  async bulkUpdateAlerts(alertIds: string[], updates: {
    status?: string;
    assignedTo?: string;
  }): Promise<ApiResponse<void>> {
    return apiClient.put('/alerts/bulk-update', { alertIds, updates });
  }
}

export const alertService = new AlertService();
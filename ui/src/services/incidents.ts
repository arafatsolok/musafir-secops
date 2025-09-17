import { apiClient } from './api';
import { Incident, CreateIncidentRequest, IncidentTimelineEntry, ApiResponse } from '../types/api';

export class IncidentService {
  async getIncidents(params?: {
    status?: string;
    severity?: string;
    assignedTo?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<Incident[]>> {
    return apiClient.get<Incident[]>('/incidents', params);
  }

  async getIncident(id: string): Promise<ApiResponse<Incident>> {
    return apiClient.get<Incident>(`/incidents/${id}`);
  }

  async createIncident(incident: CreateIncidentRequest): Promise<ApiResponse<Incident>> {
    return apiClient.post<Incident>('/incidents', incident);
  }

  async updateIncident(id: string, updates: Partial<Incident>): Promise<ApiResponse<Incident>> {
    return apiClient.put<Incident>(`/incidents/${id}`, updates);
  }

  async deleteIncident(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/incidents/${id}`);
  }

  async assignIncident(id: string, assignedTo: string): Promise<ApiResponse<Incident>> {
    return apiClient.put<Incident>(`/incidents/${id}/assign`, { assignedTo });
  }

  async updateIncidentStatus(id: string, status: string): Promise<ApiResponse<Incident>> {
    return apiClient.put<Incident>(`/incidents/${id}/status`, { status });
  }

  async addTimelineEntry(
    incidentId: string,
    entry: Omit<IncidentTimelineEntry, 'id' | 'timestamp'>
  ): Promise<ApiResponse<IncidentTimelineEntry>> {
    return apiClient.post<IncidentTimelineEntry>(`/incidents/${incidentId}/timeline`, entry);
  }

  async getIncidentTimeline(incidentId: string): Promise<ApiResponse<IncidentTimelineEntry[]>> {
    return apiClient.get<IncidentTimelineEntry[]>(`/incidents/${incidentId}/timeline`);
  }

  async getIncidentStats(): Promise<ApiResponse<{
    total: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    trends: Array<{ date: string; count: number }>;
  }>> {
    return apiClient.get('/incidents/stats');
  }
}

export const incidentService = new IncidentService();
import { apiClient } from './api';
import { DashboardMetrics, ApiResponse } from '../types/api';

export class DashboardService {
  async getDashboardMetrics(timeRange?: {
    start: string;
    end: string;
  }): Promise<ApiResponse<DashboardMetrics>> {
    return apiClient.get<DashboardMetrics>('/dashboard/metrics', timeRange);
  }

  async getSecurityOverview(): Promise<ApiResponse<{
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    activeThreats: number;
    blockedAttacks: number;
    systemHealth: number;
    lastUpdate: string;
  }>> {
    return apiClient.get('/dashboard/security-overview');
  }

  async getIncidentTrends(days: number = 30): Promise<ApiResponse<Array<{
    date: string;
    incidents: number;
    alerts: number;
    resolved: number;
  }>>> {
    return apiClient.get('/dashboard/incident-trends', { days });
  }

  async getAlertDistribution(): Promise<ApiResponse<{
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    bySource: Record<string, number>;
    hourlyDistribution: Array<{ hour: number; count: number }>;
  }>> {
    return apiClient.get('/dashboard/alert-distribution');
  }

  async getAssetHealth(): Promise<ApiResponse<{
    totalAssets: number;
    onlineAssets: number;
    criticalAssets: number;
    vulnerableAssets: number;
    complianceScore: number;
  }>> {
    return apiClient.get('/dashboard/asset-health');
  }

  async getThreatIntelligence(): Promise<ApiResponse<{
    newIndicators: number;
    highConfidenceThreats: number;
    blockedIPs: number;
    malwareFamilies: Array<{
      name: string;
      count: number;
      trend: 'up' | 'down' | 'stable';
    }>;
  }>> {
    return apiClient.get('/dashboard/threat-intelligence');
  }

  async getUserActivity(): Promise<ApiResponse<{
    activeUsers: number;
    suspiciousActivities: number;
    failedLogins: number;
    privilegedAccess: number;
    topUsers: Array<{
      username: string;
      activities: number;
      riskScore: number;
    }>;
  }>> {
    return apiClient.get('/dashboard/user-activity');
  }

  async getComplianceStatus(): Promise<ApiResponse<{
    overallScore: number;
    frameworks: Array<{
      name: string;
      score: number;
      controls: {
        total: number;
        compliant: number;
        nonCompliant: number;
      };
    }>;
  }>> {
    return apiClient.get('/dashboard/compliance');
  }

  async getSystemPerformance(): Promise<ApiResponse<{
    cpuUsage: number;
    memoryUsage: number;
    diskUsage: number;
    networkThroughput: number;
    responseTime: number;
    uptime: number;
  }>> {
    return apiClient.get('/dashboard/system-performance');
  }

  async getRecentActivities(limit: number = 20): Promise<ApiResponse<Array<{
    id: string;
    type: 'incident' | 'alert' | 'scan' | 'user_action';
    description: string;
    timestamp: string;
    severity: string;
    user?: string;
  }>>> {
    return apiClient.get('/dashboard/recent-activities', { limit });
  }
}

export const dashboardService = new DashboardService();
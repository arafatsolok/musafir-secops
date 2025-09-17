import { apiClient } from './api';
import { Asset, ApiResponse } from '../types/api';

export class AssetService {
  async getAssets(params?: {
    type?: string;
    status?: string;
    criticality?: string;
    location?: string;
    owner?: string;
    page?: number;
    limit?: number;
    search?: string;
  }): Promise<ApiResponse<Asset[]>> {
    return apiClient.get<Asset[]>('/assets', params);
  }

  async getAsset(id: string): Promise<ApiResponse<Asset>> {
    return apiClient.get<Asset>(`/assets/${id}`);
  }

  async createAsset(asset: Omit<Asset, 'id' | 'lastSeen'>): Promise<ApiResponse<Asset>> {
    return apiClient.post<Asset>('/assets', asset);
  }

  async updateAsset(id: string, updates: Partial<Asset>): Promise<ApiResponse<Asset>> {
    return apiClient.put<Asset>(`/assets/${id}`, updates);
  }

  async deleteAsset(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/assets/${id}`);
  }

  async getAssetVulnerabilities(id: string): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/assets/${id}/vulnerabilities`);
  }

  async getAssetAlerts(id: string, params?: {
    startTime?: string;
    endTime?: string;
    limit?: number;
  }): Promise<ApiResponse<any[]>> {
    return apiClient.get(`/assets/${id}/alerts`, params);
  }

  async scanAsset(id: string, scanType: 'vulnerability' | 'compliance' | 'full'): Promise<ApiResponse<{ scanId: string }>> {
    return apiClient.post(`/assets/${id}/scan`, { scanType });
  }

  async getAssetStats(): Promise<ApiResponse<{
    total: number;
    byType: Record<string, number>;
    byStatus: Record<string, number>;
    byCriticality: Record<string, number>;
    vulnerabilityDistribution: Record<string, number>;
  }>> {
    return apiClient.get('/assets/stats');
  }

  async getAssetGroups(): Promise<ApiResponse<Array<{
    id: string;
    name: string;
    description: string;
    assetCount: number;
  }>>> {
    return apiClient.get('/assets/groups');
  }

  async addAssetToGroup(assetId: string, groupId: string): Promise<ApiResponse<void>> {
    return apiClient.post(`/assets/${assetId}/groups/${groupId}`);
  }

  async removeAssetFromGroup(assetId: string, groupId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`/assets/${assetId}/groups/${groupId}`);
  }

  async bulkUpdateAssets(assetIds: string[], updates: Partial<Asset>): Promise<ApiResponse<void>> {
    return apiClient.put('/assets/bulk-update', { assetIds, updates });
  }
}

export const assetService = new AssetService();
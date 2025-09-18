import { apiClient } from './api';
import { ApiResponse } from '../types/api';

export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  department: string;
  status: 'active' | 'inactive' | 'locked' | 'pending';
  lastLogin?: string;
  createdAt: string;
  permissions: string[];
  mfaEnabled: boolean;
  phone?: string;
  location?: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
  isSystem: boolean;
  createdAt: string;
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  category: string;
  isSystem: boolean;
}

export interface AuditLog {
  id: string;
  userId: string;
  username: string;
  action: string;
  resource: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  status: 'success' | 'failed';
}

export interface CreateUserRequest {
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  department: string;
  password: string;
  phone?: string;
  location?: string;
}

export interface UpdateUserRequest {
  email?: string;
  firstName?: string;
  lastName?: string;
  role?: string;
  department?: string;
  status?: 'active' | 'inactive' | 'locked' | 'pending';
  phone?: string;
  location?: string;
}

export interface CreateRoleRequest {
  name: string;
  description: string;
  permissions: string[];
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  permissions?: string[];
}

export class UserService {
  // User Management
  async getUsers(params?: {
    status?: string;
    role?: string;
    department?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<User[]>> {
    return apiClient.get<User[]>('/users', params);
  }

  async getUser(id: string): Promise<ApiResponse<User>> {
    return apiClient.get<User>(`/users/${id}`);
  }

  async createUser(userData: CreateUserRequest): Promise<ApiResponse<User>> {
    return apiClient.post<User>('/users', userData);
  }

  async updateUser(id: string, updates: UpdateUserRequest): Promise<ApiResponse<User>> {
    return apiClient.put<User>(`/users/${id}`, updates);
  }

  async deleteUser(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${id}`);
  }

  async resetPassword(id: string, newPassword: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/reset-password`, { password: newPassword });
  }

  async lockUser(id: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/lock`);
  }

  async unlockUser(id: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/unlock`);
  }

  async enableMFA(id: string): Promise<ApiResponse<{ qrCode: string; secret: string }>> {
    return apiClient.post<{ qrCode: string; secret: string }>(`/users/${id}/mfa/enable`);
  }

  async disableMFA(id: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/mfa/disable`);
  }

  // Role Management
  async getRoles(params?: {
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<Role[]>> {
    return apiClient.get<Role[]>('/roles', params);
  }

  async getRole(id: string): Promise<ApiResponse<Role>> {
    return apiClient.get<Role>(`/roles/${id}`);
  }

  async createRole(roleData: CreateRoleRequest): Promise<ApiResponse<Role>> {
    return apiClient.post<Role>('/roles', roleData);
  }

  async updateRole(id: string, updates: UpdateRoleRequest): Promise<ApiResponse<Role>> {
    return apiClient.put<Role>(`/roles/${id}`, updates);
  }

  async deleteRole(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/roles/${id}`);
  }

  async assignRole(userId: string, roleId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${userId}/roles`, { roleId });
  }

  async removeRole(userId: string, roleId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/roles/${roleId}`);
  }

  // Permission Management
  async getPermissions(params?: {
    category?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<Permission[]>> {
    return apiClient.get<Permission[]>('/permissions', params);
  }

  async getPermission(id: string): Promise<ApiResponse<Permission>> {
    return apiClient.get<Permission>(`/permissions/${id}`);
  }

  async createPermission(permissionData: Omit<Permission, 'id' | 'isSystem'>): Promise<ApiResponse<Permission>> {
    return apiClient.post<Permission>('/permissions', permissionData);
  }

  async updatePermission(id: string, updates: Partial<Permission>): Promise<ApiResponse<Permission>> {
    return apiClient.put<Permission>(`/permissions/${id}`, updates);
  }

  async deletePermission(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/permissions/${id}`);
  }

  async getUserPermissions(userId: string): Promise<ApiResponse<Permission[]>> {
    return apiClient.get<Permission[]>(`/users/${userId}/permissions`);
  }

  async grantPermission(userId: string, permissionId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${userId}/permissions`, { permissionId });
  }

  async revokePermission(userId: string, permissionId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/permissions/${permissionId}`);
  }

  // Audit Logs
  async getAuditLogs(params?: {
    userId?: string;
    action?: string;
    resource?: string;
    status?: string;
    startDate?: string;
    endDate?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<AuditLog[]>> {
    return apiClient.get<AuditLog[]>('/audit-logs', params);
  }

  async getAuditLog(id: string): Promise<ApiResponse<AuditLog>> {
    return apiClient.get<AuditLog>(`/audit-logs/${id}`);
  }

  async createAuditLog(logData: Omit<AuditLog, 'id' | 'timestamp'>): Promise<ApiResponse<AuditLog>> {
    return apiClient.post<AuditLog>('/audit-logs', logData);
  }

  // User Sessions
  async getUserSessions(userId: string): Promise<ApiResponse<Array<{
    id: string;
    userId: string;
    ipAddress: string;
    userAgent: string;
    loginTime: string;
    lastActivity: string;
    isActive: boolean;
  }>>> {
    return apiClient.get<Array<{
      id: string;
      userId: string;
      ipAddress: string;
      userAgent: string;
      loginTime: string;
      lastActivity: string;
      isActive: boolean;
    }>>(`/users/${userId}/sessions`);
  }

  async terminateSession(userId: string, sessionId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/sessions/${sessionId}`);
  }

  async terminateAllSessions(userId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/sessions`);
  }

  // Bulk Operations
  async bulkUpdateUsers(userIds: string[], updates: UpdateUserRequest): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/users/bulk-update', { userIds, updates });
  }

  async bulkDeleteUsers(userIds: string[]): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/users/bulk-delete', { userIds });
  }

  async exportUsers(format: 'csv' | 'json' | 'xlsx'): Promise<ApiResponse<{ exportUrl: string }>> {
    return apiClient.post<{ exportUrl: string }>('/users/export', { format });
  }

  async importUsers(file: File): Promise<ApiResponse<{ imported: number; failed: number; errors: string[] }>> {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient.post<{ imported: number; failed: number; errors: string[] }>('/users/import', formData);
  }
}

export const userService = new UserService();
import { apiClient, ApiResponse } from './api';

// User Management Types
export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  department: string;
  status: 'active' | 'inactive' | 'locked' | 'suspended';
  lastLogin?: string;
  mfaEnabled: boolean;
  hardwareTokenId?: string;
  lastPasswordChange?: string;
  failedLoginAttempts: number;
  accountLockedUntil?: string;
  createdAt: string;
  updatedAt: string;
  groups?: UserGroup[];
}

// User Groups
export interface UserGroup {
  id: string;
  name: string;
  description: string;
  parentGroupId?: string;
  groupType: 'department' | 'team' | 'project' | 'custom';
  createdAt: string;
  updatedAt: string;
  memberCount?: number;
}

export interface UserGroupMembership {
  userId: string;
  groupId: string;
  roleInGroup: string;
  assignedAt: string;
  assignedBy: string;
  expiresAt?: string;
}

// Session Management
export interface UserSession {
  sessionId: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceFingerprint: string;
  location?: string;
  createdAt: string;
  lastActivity: string;
  expiresAt: string;
  status: 'active' | 'expired' | 'terminated' | 'forced_logout';
  logoutReason?: string;
}

export interface SessionActivity {
  sessionId: string;
  userId: string;
  activityType: 'login' | 'logout' | 'page_view' | 'action' | 'api_call' | 'file_access' | 'settings_change' | 'password_change' | 'mfa_challenge' | 'privilege_escalation';
  timestamp: string;
  ipAddress: string;
  resource: string;
  actionDetails: string;
  result: 'success' | 'failure' | 'blocked';
  riskScore: number;
}

// MFA Enhancement
export interface MFADevice {
  id: string;
  userId: string;
  deviceType: 'totp' | 'sms' | 'email' | 'hardware_token' | 'webauthn';
  deviceName: string;
  deviceIdentifier: string;
  isPrimary: boolean;
  isActive: boolean;
  createdAt: string;
  lastUsed?: string;
}

export interface MFAChallenge {
  challengeId: string;
  userId: string;
  deviceId: string;
  challengeType: 'login' | 'transaction' | 'admin_action';
  createdAt: string;
  expiresAt: string;
  status: 'pending' | 'completed' | 'failed' | 'expired';
  attempts: number;
}

// User Analytics
export interface UserBehaviorPattern {
  userId: string;
  patternType: 'login_time' | 'login_location' | 'device_usage' | 'resource_access' | 'action_frequency' | 'navigation_pattern' | 'session_duration' | 'api_usage' | 'file_access_pattern' | 'privilege_usage';
  patternData: any;
  confidenceScore: number;
  createdAt: string;
  updatedAt: string;
  validUntil: string;
}

export interface UserAnomaly {
  id: string;
  userId: string;
  anomalyType: 'unusual_login_time' | 'new_location' | 'new_device' | 'privilege_escalation' | 'unusual_resource_access' | 'suspicious_activity' | 'failed_authentication' | 'concurrent_sessions' | 'data_exfiltration' | 'policy_violation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidenceScore: number;
  description: string;
  detectedAt: string;
  sessionId?: string;
  ipAddress: string;
  evidence: any;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  resolvedAt?: string;
  resolvedBy?: string;
}

// Bulk Operations
export interface BulkImportJob {
  jobId: string;
  jobType: 'user_import' | 'user_export' | 'group_import' | 'role_import';
  filename: string;
  fileSize: number;
  totalRecords: number;
  processedRecords: number;
  successfulRecords: number;
  failedRecords: number;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  createdBy: string;
  errorLog?: string[];
  resultFilePath?: string;
}

// Password Policies
export interface PasswordPolicy {
  id: string;
  name: string;
  description: string;
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  forbiddenPatterns: string[];
  maxAgeDays: number;
  historyCount: number;
  lockoutThreshold: number;
  lockoutDurationMinutes: number;
  isActive: boolean;
  appliesToGroups: string[];
  createdAt: string;
  updatedAt: string;
  createdBy: string;
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
  // Existing user management methods...
  async getUsers(params?: {
    page?: number;
    limit?: number;
    search?: string;
    role?: string;
    department?: string;
    status?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<ApiResponse<User[]>> {
    return apiClient.get<User[]>('/users', params);
  }

  async getUser(id: string): Promise<ApiResponse<User>> {
    return apiClient.get<User>(`/users/${id}`);
  }

  async createUser(userData: CreateUserRequest): Promise<ApiResponse<User>> {
    return apiClient.post<User>('/users', userData);
  }

  async updateUser(id: string, userData: UpdateUserRequest): Promise<ApiResponse<User>> {
    return apiClient.put<User>(`/users/${id}`, userData);
  }

  async deleteUser(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${id}`);
  }

  async resetPassword(id: string, newPassword?: string): Promise<ApiResponse<{ temporaryPassword?: string }>> {
    return apiClient.post<{ temporaryPassword?: string }>(`/users/${id}/reset-password`, { newPassword });
  }

  async lockUser(id: string, reason?: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/lock`, { reason });
  }

  async unlockUser(id: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${id}/unlock`);
  }

  // =====================================================
  // SESSION MANAGEMENT
  // =====================================================

  async getAllActiveSessions(params?: {
    page?: number;
    limit?: number;
    userId?: string;
    ipAddress?: string;
    location?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<ApiResponse<UserSession[]>> {
    return apiClient.get<UserSession[]>('/sessions', params);
  }

  async getUserSessions(userId: string): Promise<ApiResponse<UserSession[]>> {
    return apiClient.get<UserSession[]>(`/users/${userId}/sessions`);
  }

  async getSessionDetails(sessionId: string): Promise<ApiResponse<UserSession>> {
    return apiClient.get<UserSession>(`/sessions/${sessionId}`);
  }

  async terminateSession(sessionId: string, reason?: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/sessions/${sessionId}`, { reason });
  }

  async terminateUserSessions(userId: string, reason?: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/sessions`, { reason });
  }

  async forceLogoutUser(userId: string, reason: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${userId}/force-logout`, { reason });
  }

  async getSessionActivities(sessionId: string, params?: {
    page?: number;
    limit?: number;
    activityType?: string;
  }): Promise<ApiResponse<SessionActivity[]>> {
    return apiClient.get<SessionActivity[]>(`/sessions/${sessionId}/activities`, params);
  }

  async getUserSessionStats(userId: string, timeRange?: string): Promise<ApiResponse<{
    totalSessions: number;
    activeSessions: number;
    uniqueLocations: number;
    uniqueDevices: number;
    averageSessionDuration: number;
    riskScore: number;
  }>> {
    return apiClient.get(`/users/${userId}/session-stats`, { timeRange });
  }

  // =====================================================
  // USER GROUPS MANAGEMENT
  // =====================================================

  async getUserGroups(params?: {
    page?: number;
    limit?: number;
    search?: string;
    groupType?: string;
    parentGroupId?: string;
  }): Promise<ApiResponse<UserGroup[]>> {
    return apiClient.get<UserGroup[]>('/user-groups', params);
  }

  async getUserGroup(id: string): Promise<ApiResponse<UserGroup>> {
    return apiClient.get<UserGroup>(`/user-groups/${id}`);
  }

  async createUserGroup(groupData: Omit<UserGroup, 'id' | 'createdAt' | 'updatedAt' | 'memberCount'>): Promise<ApiResponse<UserGroup>> {
    return apiClient.post<UserGroup>('/user-groups', groupData);
  }

  async updateUserGroup(id: string, groupData: Partial<UserGroup>): Promise<ApiResponse<UserGroup>> {
    return apiClient.put<UserGroup>(`/user-groups/${id}`, groupData);
  }

  async deleteUserGroup(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/user-groups/${id}`);
  }

  async getGroupMembers(groupId: string, params?: {
    page?: number;
    limit?: number;
    search?: string;
  }): Promise<ApiResponse<User[]>> {
    return apiClient.get<User[]>(`/user-groups/${groupId}/members`, params);
  }

  async addUserToGroup(userId: string, groupId: string, roleInGroup?: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/user-groups/${groupId}/members`, { userId, roleInGroup });
  }

  async removeUserFromGroup(userId: string, groupId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/user-groups/${groupId}/members/${userId}`);
  }

  async getUserGroupMemberships(userId: string): Promise<ApiResponse<UserGroupMembership[]>> {
    return apiClient.get<UserGroupMembership[]>(`/users/${userId}/groups`);
  }

  // =====================================================
  // ENHANCED MFA MANAGEMENT
  // =====================================================

  async getMFADevices(userId: string): Promise<ApiResponse<MFADevice[]>> {
    return apiClient.get<MFADevice[]>(`/users/${userId}/mfa-devices`);
  }

  async addMFADevice(userId: string, deviceData: {
    deviceType: MFADevice['deviceType'];
    deviceName: string;
    deviceIdentifier?: string;
  }): Promise<ApiResponse<MFADevice & { qrCode?: string; backupCodes?: string[] }>> {
    return apiClient.post<MFADevice & { qrCode?: string; backupCodes?: string[] }>(`/users/${userId}/mfa-devices`, deviceData);
  }

  async verifyMFADevice(userId: string, deviceId: string, verificationCode: string): Promise<ApiResponse<{ verified: boolean }>> {
    return apiClient.post<{ verified: boolean }>(`/users/${userId}/mfa-devices/${deviceId}/verify`, { verificationCode });
  }

  async removeMFADevice(userId: string, deviceId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/users/${userId}/mfa-devices/${deviceId}`);
  }

  async setPrimaryMFADevice(userId: string, deviceId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/users/${userId}/mfa-devices/${deviceId}/set-primary`);
  }

  async initWebAuthnRegistration(userId: string, deviceName: string): Promise<ApiResponse<{
    challenge: string;
    rp: any;
    user: any;
    pubKeyCredParams: any[];
    timeout: number;
  }>> {
    return apiClient.post(`/users/${userId}/webauthn/register/begin`, { deviceName });
  }

  async completeWebAuthnRegistration(userId: string, credential: any): Promise<ApiResponse<MFADevice>> {
    return apiClient.post<MFADevice>(`/users/${userId}/webauthn/register/complete`, { credential });
  }

  async getMFAChallenges(userId: string): Promise<ApiResponse<MFAChallenge[]>> {
    return apiClient.get<MFAChallenge[]>(`/users/${userId}/mfa-challenges`);
  }

  // =====================================================
  // USER BEHAVIOR ANALYTICS
  // =====================================================

  async getUserBehaviorPatterns(userId: string): Promise<ApiResponse<UserBehaviorPattern[]>> {
    return apiClient.get<UserBehaviorPattern[]>(`/users/${userId}/behavior-patterns`);
  }

  async getUserAnomalies(params?: {
    userId?: string;
    severity?: string;
    status?: string;
    startDate?: string;
    endDate?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<UserAnomaly[]>> {
    return apiClient.get<UserAnomaly[]>('/user-anomalies', params);
  }

  async getUserAnomaly(id: string): Promise<ApiResponse<UserAnomaly>> {
    return apiClient.get<UserAnomaly>(`/user-anomalies/${id}`);
  }

  async resolveUserAnomaly(id: string, resolution: {
    status: 'resolved' | 'false_positive';
    notes?: string;
  }): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/user-anomalies/${id}/resolve`, resolution);
  }

  async getUserRiskScore(userId: string): Promise<ApiResponse<{
    riskScore: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    factors: Array<{
      factor: string;
      impact: number;
      description: string;
    }>;
    lastCalculated: string;
  }>> {
    return apiClient.get(`/users/${userId}/risk-score`);
  }

  async getUserLoginAnalytics(userId: string, timeRange?: string): Promise<ApiResponse<{
    totalLogins: number;
    successfulLogins: number;
    failedLogins: number;
    uniqueLocations: number;
    uniqueDevices: number;
    loginTimes: Array<{ hour: number; count: number }>;
    locationBreakdown: Array<{ location: string; count: number }>;
    deviceBreakdown: Array<{ device: string; count: number }>;
  }>> {
    return apiClient.get(`/users/${userId}/login-analytics`, { timeRange });
  }

  // =====================================================
  // BULK OPERATIONS
  // =====================================================

  async createBulkImportJob(file: File, jobType: BulkImportJob['jobType']): Promise<ApiResponse<BulkImportJob>> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('jobType', jobType);
    return apiClient.post<BulkImportJob>('/bulk-operations/import', formData);
  }

  async getBulkImportJobs(params?: {
    page?: number;
    limit?: number;
    status?: string;
    jobType?: string;
  }): Promise<ApiResponse<BulkImportJob[]>> {
    return apiClient.get<BulkImportJob[]>('/bulk-operations/jobs', params);
  }

  async getBulkImportJob(jobId: string): Promise<ApiResponse<BulkImportJob>> {
    return apiClient.get<BulkImportJob>(`/bulk-operations/jobs/${jobId}`);
  }

  async cancelBulkImportJob(jobId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`/bulk-operations/jobs/${jobId}/cancel`);
  }

  async downloadBulkImportResult(jobId: string): Promise<ApiResponse<{ downloadUrl: string }>> {
    return apiClient.get<{ downloadUrl: string }>(`/bulk-operations/jobs/${jobId}/download`);
  }

  async exportUsers(format: 'csv' | 'xlsx' | 'json', filters?: {
    department?: string;
    role?: string;
    status?: string;
    groups?: string[];
  }): Promise<ApiResponse<{ jobId: string }>> {
    return apiClient.post<{ jobId: string }>('/users/export', { format, filters });
  }

  async getBulkImportTemplate(type: 'users' | 'groups'): Promise<ApiResponse<{ downloadUrl: string }>> {
    return apiClient.get<{ downloadUrl: string }>(`/bulk-operations/template/${type}`);
  }

  // =====================================================
  // PASSWORD POLICIES
  // =====================================================

  async getPasswordPolicies(): Promise<ApiResponse<PasswordPolicy[]>> {
    return apiClient.get<PasswordPolicy[]>('/password-policies');
  }

  async getPasswordPolicy(id: string): Promise<ApiResponse<PasswordPolicy>> {
    return apiClient.get<PasswordPolicy>(`/password-policies/${id}`);
  }

  async createPasswordPolicy(policyData: Omit<PasswordPolicy, 'id' | 'createdAt' | 'updatedAt'>): Promise<ApiResponse<PasswordPolicy>> {
    return apiClient.post<PasswordPolicy>('/password-policies', policyData);
  }

  async updatePasswordPolicy(id: string, policyData: Partial<PasswordPolicy>): Promise<ApiResponse<PasswordPolicy>> {
    return apiClient.put<PasswordPolicy>(`/password-policies/${id}`, policyData);
  }

  async deletePasswordPolicy(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/password-policies/${id}`);
  }

  async validatePassword(password: string, userId?: string): Promise<ApiResponse<{
    isValid: boolean;
    violations: Array<{
      rule: string;
      message: string;
    }>;
    strength: 'weak' | 'fair' | 'good' | 'strong';
    score: number;
  }>> {
    return apiClient.post('/password-policies/validate', { password, userId });
  }

  async getPasswordHistory(userId: string): Promise<ApiResponse<Array<{
    createdAt: string;
    expiresAt: string;
  }>>> {
    return apiClient.get(`/users/${userId}/password-history`);
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
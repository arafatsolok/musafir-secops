import { apiClient } from './api';
import { User, LoginRequest, AuthResponse, ApiResponse } from '../types/api';

export class AuthService {
  async login(credentials: LoginRequest): Promise<ApiResponse<AuthResponse>> {
    const response = await apiClient.post<AuthResponse>('/auth/login', credentials);
    
    if (response.success && response.data) {
      apiClient.setToken(response.data.token);
    }
    
    return response;
  }

  async logout(): Promise<ApiResponse<void>> {
    const response = await apiClient.post<void>('/auth/logout');
    apiClient.clearToken();
    return response;
  }

  async getCurrentUser(): Promise<ApiResponse<User>> {
    return apiClient.get<User>('/auth/me');
  }

  async refreshToken(): Promise<ApiResponse<AuthResponse>> {
    const response = await apiClient.post<AuthResponse>('/auth/refresh');
    
    if (response.success && response.data) {
      apiClient.setToken(response.data.token);
    }
    
    return response;
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>('/auth/change-password', {
      oldPassword,
      newPassword,
    });
  }

  isAuthenticated(): boolean {
    return localStorage.getItem('auth_token') !== null;
  }

  getToken(): string | null {
    return localStorage.getItem('auth_token');
  }
}

export const authService = new AuthService();
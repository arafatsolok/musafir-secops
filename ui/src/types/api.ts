// API Response Types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// User and Authentication Types
export interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'operator' | 'viewer';
  department: string;
  lastLogin?: string;
  isActive: boolean;
  permissions: string[];
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user: User;
  expiresIn: number;
}

// Incident Types
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
  affectedAssets: string[];
  timeline: IncidentTimelineEntry[];
}

export interface IncidentTimelineEntry {
  id: string;
  timestamp: string;
  action: string;
  description: string;
  user: string;
  type: 'detection' | 'investigation' | 'containment' | 'eradication' | 'recovery';
}

export interface CreateIncidentRequest {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  tags?: string[];
  affectedAssets?: string[];
}

// Alert Types
export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive';
  source: string;
  timestamp: string;
  category: string;
  affectedAssets: string[];
  ruleId?: string;
  rawData?: any;
}

// Asset Types
export interface Asset {
  id: string;
  name: string;
  type: 'server' | 'workstation' | 'network_device' | 'mobile' | 'iot' | 'cloud_resource';
  ip: string;
  os: string;
  location: string;
  owner: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: 'online' | 'offline' | 'maintenance';
  lastSeen: string;
  vulnerabilities: number;
  tags: string[];
}

// Vulnerability Types
export interface Vulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore: number;
  affectedAssets: string[];
  status: 'open' | 'patched' | 'mitigated' | 'accepted' | 'false_positive';
  discoveredAt: string;
  patchAvailable: boolean;
  exploitAvailable: boolean;
  references: string[];
}

// Threat Intelligence Types
export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  description?: string;
}

// Analytics Types
export interface DashboardMetrics {
  totalIncidents: number;
  openIncidents: number;
  criticalAlerts: number;
  assetsMonitored: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  incidentTrends: Array<{
    date: string;
    count: number;
  }>;
  alertsByCategory: Array<{
    category: string;
    count: number;
  }>;
  topThreats: Array<{
    name: string;
    count: number;
    severity: string;
  }>;
}

// Agent Types
export interface Agent {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  version: string;
  status: 'online' | 'offline' | 'error';
  lastHeartbeat: string;
  capabilities: string[];
  groups: string[];
}

// Query Types
export interface QueryRequest {
  query: string;
  timeRange?: {
    start: string;
    end: string;
  };
  limit?: number;
  offset?: number;
}

export interface QueryResult {
  columns: string[];
  rows: any[][];
  totalRows: number;
  executionTime: number;
}

// Compliance Types
export interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls: ComplianceControl[];
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_assessed';
  lastAssessed: string;
  evidence: string[];
}

// Forensics Types
export interface ForensicsCase {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'closed' | 'archived';
  investigator: string;
  createdAt: string;
  evidence: Evidence[];
}

export interface Evidence {
  id: string;
  name: string;
  type: 'disk_image' | 'memory_dump' | 'network_capture' | 'log_file' | 'file_system';
  size: number;
  hash: string;
  collectedAt: string;
  source: string;
}
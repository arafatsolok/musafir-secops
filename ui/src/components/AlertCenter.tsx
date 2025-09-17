import React, { useState, useEffect } from 'react';
import { 
  Bell, 
  AlertTriangle, 
  Shield, 
  Activity, 
  Clock, 
  Filter, 
  Search, 
  Eye, 
  CheckCircle, 
  XCircle, 
  AlertCircle,
  TrendingUp,
  Users,
  Server,
  Network,
  Lock,
  Zap,
  BarChart3,
  Settings,
  Download,
  RefreshCw
} from 'lucide-react';

interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'malware' | 'network' | 'endpoint' | 'user' | 'compliance' | 'system';
  timestamp: string;
  source: string;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  assignee?: string;
  affectedAssets: number;
  riskScore: number;
}

interface MonitoringMetric {
  id: string;
  name: string;
  value: number;
  unit: string;
  status: 'normal' | 'warning' | 'critical';
  trend: 'up' | 'down' | 'stable';
  change: number;
}

interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  conditions: string;
  actions: string[];
  lastTriggered?: string;
  triggerCount: number;
}

const AlertCenter: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'alerts' | 'monitoring' | 'rules' | 'analytics'>('alerts');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<MonitoringMetric[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading data
    setTimeout(() => {
      setAlerts([
        {
          id: 'ALT-001',
          title: 'Suspicious PowerShell Execution',
          description: 'Encoded PowerShell command detected on endpoint DESKTOP-001',
          severity: 'critical',
          category: 'endpoint',
          timestamp: '2024-01-15T14:30:00Z',
          source: 'EDR Agent',
          status: 'new',
          affectedAssets: 1,
          riskScore: 95
        },
        {
          id: 'ALT-002',
          title: 'Multiple Failed Login Attempts',
          description: 'User account admin@company.com has 15 failed login attempts',
          severity: 'high',
          category: 'user',
          timestamp: '2024-01-15T14:25:00Z',
          source: 'SIEM Correlation',
          status: 'investigating',
          assignee: 'John Doe',
          affectedAssets: 1,
          riskScore: 78
        },
        {
          id: 'ALT-003',
          title: 'Unusual Network Traffic',
          description: 'High volume of outbound traffic to suspicious IP 192.168.1.100',
          severity: 'medium',
          category: 'network',
          timestamp: '2024-01-15T14:20:00Z',
          source: 'Network Monitor',
          status: 'new',
          affectedAssets: 3,
          riskScore: 65
        }
      ]);

      setMetrics([
        { id: '1', name: 'Active Endpoints', value: 1247, unit: 'devices', status: 'normal', trend: 'up', change: 2.3 },
        { id: '2', name: 'Events/Second', value: 15420, unit: 'eps', status: 'normal', trend: 'stable', change: 0.1 },
        { id: '3', name: 'CPU Usage', value: 67, unit: '%', status: 'warning', trend: 'up', change: 12.5 },
        { id: '4', name: 'Memory Usage', value: 78, unit: '%', status: 'warning', trend: 'up', change: 8.2 },
        { id: '5', name: 'Disk I/O', value: 234, unit: 'MB/s', status: 'normal', trend: 'down', change: -5.1 },
        { id: '6', name: 'Network Latency', value: 45, unit: 'ms', status: 'normal', trend: 'stable', change: 0.8 }
      ]);

      setRules([
        {
          id: 'RULE-001',
          name: 'Malware Detection',
          description: 'Detect known malware signatures and behaviors',
          enabled: true,
          severity: 'critical',
          conditions: 'file_hash IN malware_db OR behavior_score > 90',
          actions: ['quarantine', 'alert', 'notify_admin'],
          lastTriggered: '2024-01-15T14:30:00Z',
          triggerCount: 23
        },
        {
          id: 'RULE-002',
          name: 'Brute Force Attack',
          description: 'Detect brute force login attempts',
          enabled: true,
          severity: 'high',
          conditions: 'failed_logins > 10 IN 5_minutes',
          actions: ['block_ip', 'alert', 'lock_account'],
          lastTriggered: '2024-01-15T14:25:00Z',
          triggerCount: 8
        },
        {
          id: 'RULE-003',
          name: 'Data Exfiltration',
          description: 'Detect unusual data transfer patterns',
          enabled: true,
          severity: 'high',
          conditions: 'outbound_data > 1GB AND destination NOT IN whitelist',
          actions: ['alert', 'block_transfer', 'investigate'],
          triggerCount: 3
        }
      ]);

      setIsLoading(false);
    }, 1000);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'new': return 'text-red-600 bg-red-50';
      case 'investigating': return 'text-yellow-600 bg-yellow-50';
      case 'resolved': return 'text-green-600 bg-green-50';
      case 'false_positive': return 'text-gray-600 bg-gray-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'normal': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'critical': return <XCircle className="w-4 h-4 text-red-500" />;
      default: return <AlertCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="w-4 h-4 text-green-500" />;
      case 'down': return <TrendingUp className="w-4 h-4 text-red-500 rotate-180" />;
      case 'stable': return <Activity className="w-4 h-4 text-gray-500" />;
      default: return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity;
    const matchesCategory = filterCategory === 'all' || alert.category === filterCategory;
    const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesCategory && matchesSearch;
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Alert & Monitoring Center</h1>
          <p className="text-gray-600">Real-time security monitoring and alert management</p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Alerts</p>
                <p className="text-2xl font-bold text-red-600">{alerts.filter(a => a.status === 'new').length}</p>
              </div>
              <Bell className="h-8 w-8 text-red-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Critical Alerts</p>
                <p className="text-2xl font-bold text-orange-600">{alerts.filter(a => a.severity === 'critical').length}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-orange-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Under Investigation</p>
                <p className="text-2xl font-bold text-yellow-600">{alerts.filter(a => a.status === 'investigating').length}</p>
              </div>
              <Eye className="h-8 w-8 text-yellow-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Avg Response Time</p>
                <p className="text-2xl font-bold text-green-600">4.2m</p>
              </div>
              <Clock className="h-8 w-8 text-green-600" />
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              {[
                { id: 'alerts', name: 'Active Alerts', icon: Bell },
                { id: 'monitoring', name: 'System Monitoring', icon: Activity },
                { id: 'rules', name: 'Alert Rules', icon: Settings },
                { id: 'analytics', name: 'Analytics', icon: BarChart3 }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.name}</span>
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'alerts' && (
              <div>
                {/* Filters */}
                <div className="flex flex-wrap gap-4 mb-6">
                  <div className="flex items-center space-x-2">
                    <Search className="w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search alerts..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                    />
                  </div>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                  >
                    <option value="all">All Categories</option>
                    <option value="malware">Malware</option>
                    <option value="network">Network</option>
                    <option value="endpoint">Endpoint</option>
                    <option value="user">User</option>
                    <option value="compliance">Compliance</option>
                    <option value="system">System</option>
                  </select>
                  <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                    <RefreshCw className="w-4 h-4" />
                    <span>Refresh</span>
                  </button>
                </div>

                {/* Alerts List */}
                <div className="space-y-4">
                  {filteredAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => setSelectedAlert(alert)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                              {alert.severity.toUpperCase()}
                            </span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(alert.status)}`}>
                              {alert.status.replace('_', ' ').toUpperCase()}
                            </span>
                            <span className="text-xs text-gray-500">{alert.id}</span>
                          </div>
                          <h3 className="text-lg font-semibold text-gray-900 mb-1">{alert.title}</h3>
                          <p className="text-gray-600 mb-2">{alert.description}</p>
                          <div className="flex items-center space-x-4 text-sm text-gray-500">
                            <span>Source: {alert.source}</span>
                            <span>Assets: {alert.affectedAssets}</span>
                            <span>Risk Score: {alert.riskScore}</span>
                            <span>{new Date(alert.timestamp).toLocaleString()}</span>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <button className="p-2 text-gray-400 hover:text-gray-600">
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'monitoring' && (
              <div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {metrics.map((metric) => (
                    <div key={metric.id} className="border border-gray-200 rounded-lg p-6">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-gray-900">{metric.name}</h3>
                        {getStatusIcon(metric.status)}
                      </div>
                      <div className="flex items-end justify-between">
                        <div>
                          <p className="text-3xl font-bold text-gray-900">
                            {metric.value.toLocaleString()}
                          </p>
                          <p className="text-sm text-gray-500">{metric.unit}</p>
                        </div>
                        <div className="flex items-center space-x-1">
                          {getTrendIcon(metric.trend)}
                          <span className={`text-sm ${metric.change >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                            {metric.change >= 0 ? '+' : ''}{metric.change}%
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'rules' && (
              <div>
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-semibold text-gray-900">Alert Rules Configuration</h3>
                  <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">
                    Create New Rule
                  </button>
                </div>
                <div className="space-y-4">
                  {rules.map((rule) => (
                    <div key={rule.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                              {rule.severity.toUpperCase()}
                            </span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${rule.enabled ? 'text-green-600 bg-green-50' : 'text-gray-600 bg-gray-50'}`}>
                              {rule.enabled ? 'ENABLED' : 'DISABLED'}
                            </span>
                          </div>
                          <h3 className="text-lg font-semibold text-gray-900 mb-1">{rule.name}</h3>
                          <p className="text-gray-600 mb-2">{rule.description}</p>
                          <div className="text-sm text-gray-500 space-y-1">
                            <p><strong>Conditions:</strong> {rule.conditions}</p>
                            <p><strong>Actions:</strong> {rule.actions.join(', ')}</p>
                            <div className="flex items-center space-x-4">
                              <span>Triggers: {rule.triggerCount}</span>
                              {rule.lastTriggered && (
                                <span>Last: {new Date(rule.lastTriggered).toLocaleString()}</span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <button className="p-2 text-gray-400 hover:text-gray-600">
                            <Settings className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'analytics' && (
              <div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="border border-gray-200 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Alert Trends (Last 7 Days)</h3>
                    <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
                      <p className="text-gray-500">Chart visualization would be here</p>
                    </div>
                  </div>
                  <div className="border border-gray-200 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Alert Categories</h3>
                    <div className="space-y-3">
                      {['Endpoint Security', 'Network Anomalies', 'User Behavior', 'Malware Detection', 'Compliance'].map((category, index) => (
                        <div key={category} className="flex items-center justify-between">
                          <span className="text-gray-700">{category}</span>
                          <div className="flex items-center space-x-2">
                            <div className="w-24 bg-gray-200 rounded-full h-2">
                              <div 
                                className="bg-blue-600 h-2 rounded-full" 
                                style={{ width: `${(5 - index) * 20}%` }}
                              ></div>
                            </div>
                            <span className="text-sm text-gray-500">{(5 - index) * 20}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertCenter;
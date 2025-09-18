import React, { useState, useEffect } from 'react';
import {
  TrendingUp, TrendingDown, AlertTriangle, Shield, Clock,
  MapPin, Monitor, Smartphone, Globe, Activity, Eye,
  Calendar, BarChart3, PieChart, LineChart, Filter,
  Download, RefreshCw, Search, Users, Target, Zap,
  User, Database, Lock
} from 'lucide-react';

interface BehaviorMetrics {
  totalUsers: number;
  activeUsers: number;
  suspiciousActivities: number;
  riskScore: number;
  loginAttempts: number;
  failedLogins: number;
  uniqueLocations: number;
  deviceCount: number;
}

interface LoginPattern {
  userId: string;
  username: string;
  email: string;
  loginTimes: string[];
  locations: string[];
  devices: string[];
  riskScore: number;
  anomalies: string[];
  lastLogin: string;
  loginFrequency: 'high' | 'medium' | 'low';
}

interface TimeSeriesData {
  timestamp: string;
  logins: number;
  failures: number;
  anomalies: number;
}

interface Anomaly {
  id: string;
  userId: string;
  username: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: string;
  location: string;
  device: string;
  confidence: number;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
}

const UserBehaviorAnalytics: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'patterns' | 'anomalies' | 'locations'>('overview');
  const [metrics, setMetrics] = useState<BehaviorMetrics>({
    totalUsers: 1247,
    activeUsers: 342,
    suspiciousActivities: 23,
    riskScore: 74,
    loginAttempts: 8945,
    failedLogins: 127,
    uniqueLocations: 45,
    deviceCount: 892
  });
  const [patterns, setPatterns] = useState<LoginPattern[]>([
    {
      userId: '1',
      username: 'jsmith',
      email: 'john.smith@company.com',
      loginTimes: ['09:00', '12:30', '17:45'],
      locations: ['New York, NY', 'Remote'],
      devices: ['Windows Desktop', 'iPhone'],
      riskScore: 85,
      anomalies: ['Off-hours access', 'New location'],
      lastLogin: '2024-01-15 16:30:00',
      loginFrequency: 'high'
    },
    {
      userId: '2',
      username: 'mjohnson',
      email: 'mary.johnson@company.com',
      loginTimes: ['08:30', '14:00'],
      locations: ['San Francisco, CA'],
      devices: ['MacBook Pro'],
      riskScore: 45,
      anomalies: [],
      lastLogin: '2024-01-15 15:45:00',
      loginFrequency: 'medium'
    }
  ]);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([
    {
      id: '1',
      userId: '1',
      username: 'jsmith',
      type: 'login',
      severity: 'high',
      description: 'Unusual login time - 3:00 AM outside normal business hours',
      timestamp: '2024-01-15 03:00:00',
      location: 'Unknown Location',
      device: 'Mobile Device',
      confidence: 87,
      status: 'new'
    },
    {
      id: '2',
      userId: '3',
      username: 'rbrown',
      type: 'data',
      severity: 'critical',
      description: 'Massive data download - 500MB in 10 minutes',
      timestamp: '2024-01-15 14:30:00',
      location: 'Chicago, IL',
      device: 'Laptop',
      confidence: 95,
      status: 'investigating'
    }
  ]);
  const [timeSeriesData, setTimeSeriesData] = useState<TimeSeriesData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [dateRange, setDateRange] = useState('7d');

  // Filter patterns based on search and risk level
  const filteredPatterns = patterns.filter(pattern => {
    const matchesSearch = pattern.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         pattern.email.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = riskFilter === 'all' || 
                       (riskFilter === 'high' && pattern.riskScore >= 70) ||
                       (riskFilter === 'medium' && pattern.riskScore >= 40 && pattern.riskScore < 70) ||
                       (riskFilter === 'low' && pattern.riskScore < 40);
    return matchesSearch && matchesRisk;
  });

  // Filter anomalies based on search
  const filteredAnomalies = anomalies.filter(anomaly => 
    anomaly.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    anomaly.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 70) return 'text-red-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">User Behavior Analytics</h2>
          <p className="mt-1 text-sm text-gray-500">
            Monitor login patterns, detect anomalies, and analyze user behavior
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-3">
          <select
            value={dateRange}
            onChange={(e) => setDateRange(e.target.value)}
            className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
          <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Users className="h-6 w-6 text-gray-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Active Users</dt>
                  <dd className="text-lg font-medium text-gray-900">{metrics.activeUsers.toLocaleString()}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-6 w-6 text-red-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Suspicious Activities</dt>
                  <dd className="text-lg font-medium text-gray-900">{metrics.suspiciousActivities}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Shield className="h-6 w-6 text-yellow-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Avg Risk Score</dt>
                  <dd className="text-lg font-medium text-gray-900">{metrics.riskScore}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Activity className="h-6 w-6 text-blue-400" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Login Attempts</dt>
                  <dd className="text-lg font-medium text-gray-900">{metrics.loginAttempts.toLocaleString()}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'overview', name: 'Overview', icon: BarChart3 },
            { id: 'patterns', name: 'Login Patterns', icon: Target },
            { id: 'anomalies', name: 'Anomalies', icon: AlertTriangle },
            { id: 'locations', name: 'Locations', icon: MapPin }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              } whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm flex items-center`}
            >
              <tab.icon className="h-4 w-4 mr-2" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Time Series Chart */}
          <div className="bg-white shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Login Activity Trends</h3>
            <div className="h-64 flex items-center justify-center bg-gray-50 rounded-lg">
              <div className="text-center">
                <LineChart className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500">Time series chart would be rendered here</p>
              </div>
            </div>
          </div>

          {/* Risk Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Risk Score Distribution</h3>
              <div className="h-48 flex items-center justify-center bg-gray-50 rounded-lg">
                <div className="text-center">
                  <PieChart className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                  <p className="text-sm text-gray-500">Risk distribution chart</p>
                </div>
              </div>
            </div>

            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Device Usage</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Monitor className="h-4 w-4 text-gray-400 mr-2" />
                    <span className="text-sm text-gray-600">Desktop</span>
                  </div>
                  <span className="text-sm font-medium text-gray-900">65%</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Smartphone className="h-4 w-4 text-gray-400 mr-2" />
                    <span className="text-sm text-gray-600">Mobile</span>
                  </div>
                  <span className="text-sm font-medium text-gray-900">28%</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Globe className="h-4 w-4 text-gray-400 mr-2" />
                    <span className="text-sm text-gray-600">Web</span>
                  </div>
                  <span className="text-sm font-medium text-gray-900">7%</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'patterns' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white shadow rounded-lg p-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0 sm:space-x-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search users..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
              <div className="flex items-center space-x-3">
                <select
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value as any)}
                  className="rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                >
                  <option value="all">All Risk Levels</option>
                  <option value="high">High Risk</option>
                  <option value="medium">Medium Risk</option>
                  <option value="low">Low Risk</option>
                </select>
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </button>
              </div>
            </div>
          </div>

          {/* Patterns Table */}
          <div className="bg-white shadow rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Login Frequency</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Locations</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Devices</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Anomalies</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredPatterns.map((pattern) => (
                  <tr key={pattern.userId} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <User className="h-8 w-8 text-gray-400" />
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">{pattern.username}</div>
                          <div className="text-sm text-gray-500">{pattern.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`text-sm font-medium ${getRiskScoreColor(pattern.riskScore)}`}>
                        {pattern.riskScore}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        pattern.loginFrequency === 'high' ? 'bg-red-100 text-red-800' :
                        pattern.loginFrequency === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-green-100 text-green-800'
                      }`}>
                        {pattern.loginFrequency}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {pattern.locations.length}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {pattern.devices.length}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {pattern.anomalies.length}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(pattern.lastLogin).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'anomalies' && (
        <div className="space-y-6">
          {/* Search */}
          <div className="bg-white shadow rounded-lg p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search anomalies..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          {/* Anomalies List */}
          <div className="space-y-4">
            {filteredAnomalies.map((anomaly) => (
              <div key={anomaly.id} className="bg-white shadow rounded-lg p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <AlertTriangle className={`h-6 w-6 mt-1 ${
                      anomaly.severity === 'critical' ? 'text-red-500' :
                      anomaly.severity === 'high' ? 'text-orange-500' :
                      anomaly.severity === 'medium' ? 'text-yellow-500' :
                      'text-green-500'
                    }`} />
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <h4 className="text-lg font-medium text-gray-900">{anomaly.username}</h4>
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(anomaly.severity)}`}>
                          {anomaly.severity}
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-gray-600">{anomaly.description}</p>
                      <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500">
                        <span className="flex items-center">
                          <Clock className="h-4 w-4 mr-1" />
                          {new Date(anomaly.timestamp).toLocaleString()}
                        </span>
                        <span className="flex items-center">
                          <MapPin className="h-4 w-4 mr-1" />
                          {anomaly.location}
                        </span>
                        <span className="flex items-center">
                          <Monitor className="h-4 w-4 mr-1" />
                          {anomaly.device}
                        </span>
                        <span>Confidence: {anomaly.confidence}%</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <select
                      value={anomaly.status}
                      onChange={(e) => {
                        // Handle status change
                      }}
                      className="text-sm border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="new">New</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'locations' && (
        <div className="space-y-6">
          <div className="bg-white shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Geographic Distribution</h3>
            <div className="h-96 flex items-center justify-center bg-gray-50 rounded-lg">
              <div className="text-center">
                <Globe className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500">World map with login locations would be rendered here</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Top Locations</h3>
              <div className="space-y-3">
                {['New York, NY', 'San Francisco, CA', 'Chicago, IL', 'Los Angeles, CA', 'Boston, MA'].map((location, index) => (
                  <div key={location} className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">{location}</span>
                    <span className="text-sm font-medium text-gray-900">{Math.floor(Math.random() * 100) + 50} logins</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Suspicious Locations</h3>
              <div className="space-y-3">
                {['Unknown Location', 'Miami, FL (New)', 'Seattle, WA (VPN)', 'Austin, TX (Off-hours)'].map((location, index) => (
                  <div key={location} className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">{location}</span>
                    <span className="text-sm font-medium text-red-600">{Math.floor(Math.random() * 10) + 1} alerts</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserBehaviorAnalytics;
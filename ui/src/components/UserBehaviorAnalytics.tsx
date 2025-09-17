import React, { useState } from 'react'
import { 
  User, 
  Users, 
  AlertTriangle, 
  TrendingUp, 
  TrendingDown,
  Clock,
  MapPin,
  Eye,
  Activity,
  BarChart3,
  Search,
  Download,
  RefreshCw,
  Zap,
  Database,
  Lock
} from 'lucide-react'

interface UserProfile {
  id: string
  username: string
  full_name: string
  email: string
  department: string
  role: string
  risk_score: number
  last_login: string
  login_count_24h: number
  failed_logins_24h: number
  data_access_24h: number
  anomalies_24h: number
  location: string
  device_count: number
  privileged_access: boolean
  status: 'active' | 'inactive' | 'suspended' | 'locked'
}

interface Anomaly {
  id: string
  user_id: string
  username: string
  type: 'login' | 'access' | 'data' | 'behavior' | 'location' | 'time'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  timestamp: string
  location: string
  device: string
  confidence: number
  status: 'new' | 'investigating' | 'resolved' | 'false_positive'
}

interface RiskMetric {
  category: string
  score: number
  trend: 'up' | 'down' | 'stable'
  description: string
}

const UserBehaviorAnalytics: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'anomalies' | 'patterns' | 'insights'>('overview')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedDepartment, setSelectedDepartment] = useState<string>('all')
  const [selectedRiskLevel, setSelectedRiskLevel] = useState<string>('all')
  const [timeRange, setTimeRange] = useState<string>('24h')

  const [users] = useState<UserProfile[]>([
    {
      id: '1',
      username: 'jsmith',
      full_name: 'John Smith',
      email: 'john.smith@company.com',
      department: 'Finance',
      role: 'Senior Analyst',
      risk_score: 85,
      last_login: '2024-01-15 16:30:00',
      login_count_24h: 12,
      failed_logins_24h: 0,
      data_access_24h: 45,
      anomalies_24h: 2,
      location: 'New York, NY',
      device_count: 3,
      privileged_access: false,
      status: 'active'
    },
    {
      id: '2',
      username: 'mjohnson',
      full_name: 'Mary Johnson',
      email: 'mary.johnson@company.com',
      department: 'IT',
      role: 'System Administrator',
      risk_score: 45,
      last_login: '2024-01-15 15:45:00',
      login_count_24h: 8,
      failed_logins_24h: 1,
      data_access_24h: 120,
      anomalies_24h: 0,
      location: 'San Francisco, CA',
      device_count: 2,
      privileged_access: true,
      status: 'active'
    },
    {
      id: '3',
      username: 'rbrown',
      full_name: 'Robert Brown',
      email: 'robert.brown@company.com',
      department: 'Sales',
      role: 'Sales Manager',
      risk_score: 92,
      last_login: '2024-01-15 14:20:00',
      login_count_24h: 25,
      failed_logins_24h: 3,
      data_access_24h: 200,
      anomalies_24h: 5,
      location: 'Chicago, IL',
      device_count: 4,
      privileged_access: false,
      status: 'active'
    }
  ])

  const [anomalies] = useState<Anomaly[]>([
    {
      id: '1',
      user_id: '1',
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
      user_id: '3',
      username: 'rbrown',
      type: 'data',
      severity: 'critical',
      description: 'Massive data download - 500MB in 10 minutes',
      timestamp: '2024-01-15 14:30:00',
      location: 'Chicago, IL',
      device: 'Laptop',
      confidence: 95,
      status: 'investigating'
    },
    {
      id: '3',
      user_id: '1',
      username: 'jsmith',
      type: 'location',
      severity: 'medium',
      description: 'Login from new geographic location',
      timestamp: '2024-01-15 16:15:00',
      location: 'Miami, FL',
      device: 'Desktop',
      confidence: 72,
      status: 'new'
    },
    {
      id: '4',
      user_id: '3',
      username: 'rbrown',
      type: 'behavior',
      severity: 'high',
      description: 'Accessing systems outside normal pattern',
      timestamp: '2024-01-15 13:45:00',
      location: 'Chicago, IL',
      device: 'Mobile Device',
      confidence: 89,
      status: 'new'
    }
  ])

  const [riskMetrics] = useState<RiskMetric[]>([
    {
      category: 'Login Anomalies',
      score: 78,
      trend: 'up',
      description: 'Unusual login patterns detected'
    },
    {
      category: 'Data Access',
      score: 65,
      trend: 'stable',
      description: 'Normal data access patterns'
    },
    {
      category: 'Geographic Risk',
      score: 82,
      trend: 'up',
      description: 'Increased foreign login attempts'
    },
    {
      category: 'Privilege Escalation',
      score: 45,
      trend: 'down',
      description: 'Reduced privilege abuse attempts'
    }
  ])

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-700 bg-red-100'
    if (score >= 60) return 'text-orange-700 bg-orange-100'
    if (score >= 40) return 'text-yellow-700 bg-yellow-100'
    return 'text-green-700 bg-green-100'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'high':
        return 'text-orange-700 bg-orange-100 border-orange-200'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'low':
        return 'text-green-700 bg-green-100 border-green-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-700 bg-green-100'
      case 'inactive':
        return 'text-gray-700 bg-gray-100'
      case 'suspended':
        return 'text-orange-700 bg-orange-100'
      case 'locked':
        return 'text-red-700 bg-red-100'
      case 'new':
        return 'text-blue-700 bg-blue-100'
      case 'investigating':
        return 'text-yellow-700 bg-yellow-100'
      case 'resolved':
        return 'text-green-700 bg-green-100'
      case 'false_positive':
        return 'text-gray-700 bg-gray-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const getAnomalyIcon = (type: string) => {
    switch (type) {
      case 'login':
        return <User className="h-4 w-4 text-blue-600" />
      case 'access':
        return <Lock className="h-4 w-4 text-purple-600" />
      case 'data':
        return <Database className="h-4 w-4 text-green-600" />
      case 'behavior':
        return <Activity className="h-4 w-4 text-orange-600" />
      case 'location':
        return <MapPin className="h-4 w-4 text-red-600" />
      case 'time':
        return <Clock className="h-4 w-4 text-yellow-600" />
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-600" />
    }
  }

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-4 w-4 text-red-600" />
      case 'down':
        return <TrendingDown className="h-4 w-4 text-green-600" />
      case 'stable':
        return <Activity className="h-4 w-4 text-gray-600" />
      default:
        return <Activity className="h-4 w-4 text-gray-600" />
    }
  }

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesDepartment = selectedDepartment === 'all' || user.department === selectedDepartment
    const matchesRisk = selectedRiskLevel === 'all' || 
                       (selectedRiskLevel === 'high' && user.risk_score >= 80) ||
                       (selectedRiskLevel === 'medium' && user.risk_score >= 40 && user.risk_score < 80) ||
                       (selectedRiskLevel === 'low' && user.risk_score < 40)
    return matchesSearch && matchesDepartment && matchesRisk
  })

  const totalUsers = users.length
  const highRiskUsers = users.filter(u => u.risk_score >= 80).length
  const totalAnomalies = anomalies.length
  const criticalAnomalies = anomalies.filter(a => a.severity === 'critical').length

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">User Behavior Analytics</h1>
            <p className="text-gray-600">Monitor user activities and detect behavioral anomalies</p>
          </div>
          <div className="flex space-x-3">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <RefreshCw className="h-4 w-4" />
              <span>Refresh</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <Download className="h-4 w-4" />
              <span>Export</span>
            </button>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Users className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Users</p>
              <p className="text-2xl font-semibold text-gray-900">{totalUsers}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertTriangle className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">High Risk Users</p>
              <p className="text-2xl font-semibold text-gray-900">{highRiskUsers}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Activity className="h-8 w-8 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Anomalies (24h)</p>
              <p className="text-2xl font-semibold text-gray-900">{totalAnomalies}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Zap className="h-8 w-8 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Critical Alerts</p>
              <p className="text-2xl font-semibold text-gray-900">{criticalAnomalies}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'users', label: 'Users', icon: Users },
            { id: 'anomalies', label: 'Anomalies', icon: AlertTriangle },
            { id: 'patterns', label: 'Patterns', icon: TrendingUp },
            { id: 'insights', label: 'Insights', icon: Eye }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-5 w-5" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Risk Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Categories</h3>
              <div className="space-y-4">
                {riskMetrics.map((metric, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getTrendIcon(metric.trend)}
                      <div>
                        <p className="text-sm font-medium text-gray-900">{metric.category}</p>
                        <p className="text-xs text-gray-500">{metric.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${
                            metric.score >= 80 ? 'bg-red-600' :
                            metric.score >= 60 ? 'bg-orange-600' :
                            metric.score >= 40 ? 'bg-yellow-600' :
                            'bg-green-600'
                          }`}
                          style={{ width: `${metric.score}%` }}
                        ></div>
                      </div>
                      <span className="text-sm font-medium text-gray-900">{metric.score}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Critical anomaly detected</p>
                    <p className="text-xs text-gray-500">User rbrown - Massive data download</p>
                    <p className="text-xs text-gray-400">2 minutes ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Unusual login time</p>
                    <p className="text-xs text-gray-500">User jsmith - 3:00 AM login</p>
                    <p className="text-xs text-gray-400">1 hour ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">New location login</p>
                    <p className="text-xs text-gray-500">User jsmith - Miami, FL</p>
                    <p className="text-xs text-gray-400">2 hours ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Behavioral pattern change</p>
                    <p className="text-xs text-gray-500">User rbrown - System access pattern</p>
                    <p className="text-xs text-gray-400">3 hours ago</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Top Risk Users */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Top Risk Users</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {users.sort((a, b) => b.risk_score - a.risk_score).slice(0, 5).map((user) => (
                <div key={user.id} className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <User className="h-8 w-8 text-gray-600" />
                      <div>
                        <h4 className="font-medium text-gray-900">{user.full_name}</h4>
                        <p className="text-sm text-gray-600">{user.department} • {user.role}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <p className="text-sm text-gray-600">Risk Score</p>
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskScoreColor(user.risk_score)}`}>
                          {user.risk_score}
                        </span>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-600">Anomalies (24h)</p>
                        <p className="text-sm font-medium text-gray-900">{user.anomalies_24h}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Users Tab */}
      {activeTab === 'users' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white rounded-lg shadow-sm p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search users..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <select
                value={selectedDepartment}
                onChange={(e) => setSelectedDepartment(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Departments</option>
                <option value="Finance">Finance</option>
                <option value="IT">IT</option>
                <option value="Sales">Sales</option>
                <option value="HR">HR</option>
                <option value="Marketing">Marketing</option>
              </select>
              <select
                value={selectedRiskLevel}
                onChange={(e) => setSelectedRiskLevel(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Risk Levels</option>
                <option value="high">High Risk (80+)</option>
                <option value="medium">Medium Risk (40-79)</option>
                <option value="low">Low Risk (&lt;40)</option>
              </select>
            </div>
          </div>

          {/* Users List */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Users ({filteredUsers.length})</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {filteredUsers.map((user) => (
                <div key={user.id} className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <User className="h-8 w-8 text-gray-600" />
                      <div>
                        <h4 className="font-medium text-gray-900">{user.full_name}</h4>
                        <p className="text-sm text-gray-600">{user.username} • {user.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(user.status)}`}>
                        {user.status.toUpperCase()}
                      </span>
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskScoreColor(user.risk_score)}`}>
                        Risk: {user.risk_score}
                      </span>
                      {user.privileged_access && (
                        <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full text-purple-700 bg-purple-100">
                          PRIVILEGED
                        </span>
                      )}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-6 gap-4 mb-4">
                    <div>
                      <span className="text-xs font-medium text-gray-500">Department</span>
                      <p className="text-sm text-gray-900">{user.department}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Role</span>
                      <p className="text-sm text-gray-900">{user.role}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Location</span>
                      <p className="text-sm text-gray-900">{user.location}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Last Login</span>
                      <p className="text-sm text-gray-900">{new Date(user.last_login).toLocaleString()}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Devices</span>
                      <p className="text-sm text-gray-900">{user.device_count}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Anomalies (24h)</span>
                      <p className="text-sm text-gray-900">{user.anomalies_24h}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-6 text-sm text-gray-600">
                      <span>Logins: {user.login_count_24h}</span>
                      <span>Failed: {user.failed_logins_24h}</span>
                      <span>Data Access: {user.data_access_24h}MB</span>
                    </div>
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-800">
                        <Eye className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Anomalies Tab */}
      {activeTab === 'anomalies' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Behavioral Anomalies</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {anomalies.map((anomaly) => (
                <div key={anomaly.id} className="p-6">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start space-x-3">
                      {getAnomalyIcon(anomaly.type)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-medium text-gray-900">{anomaly.username}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(anomaly.severity)}`}>
                            {anomaly.severity.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mb-2">{anomaly.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Type: {anomaly.type.toUpperCase()}</span>
                          <span>Location: {anomaly.location}</span>
                          <span>Device: {anomaly.device}</span>
                          <span>Confidence: {anomaly.confidence}%</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(anomaly.status)}`}>
                        {anomaly.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-gray-500">
                      {new Date(anomaly.timestamp).toLocaleString()}
                    </div>
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-800 text-sm">
                        Investigate
                      </button>
                      <button className="text-green-600 hover:text-green-800 text-sm">
                        Mark Resolved
                      </button>
                      <button className="text-gray-600 hover:text-gray-800 text-sm">
                        False Positive
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Patterns Tab */}
      {activeTab === 'patterns' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Login Patterns</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Peak Hours</span>
                  <span className="text-sm font-medium text-gray-900">9:00 AM - 11:00 AM</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Off-Hours Activity</span>
                  <span className="text-sm font-medium text-red-600">↑ 15%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Weekend Logins</span>
                  <span className="text-sm font-medium text-orange-600">↑ 8%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Failed Login Rate</span>
                  <span className="text-sm font-medium text-green-600">↓ 3%</span>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Access Patterns</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Data Downloads</span>
                  <span className="text-sm font-medium text-red-600">↑ 25%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">System Access</span>
                  <span className="text-sm font-medium text-gray-900">Normal</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">File Sharing</span>
                  <span className="text-sm font-medium text-yellow-600">↑ 12%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Email Activity</span>
                  <span className="text-sm font-medium text-green-600">↓ 5%</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Geographic Distribution</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <p className="text-2xl font-semibold text-gray-900">78%</p>
                <p className="text-sm text-gray-600">Domestic Logins</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-semibold text-orange-600">18%</p>
                <p className="text-sm text-gray-600">International Logins</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-semibold text-red-600">4%</p>
                <p className="text-sm text-gray-600">Suspicious Locations</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Insights Tab */}
      {activeTab === 'insights' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Key Insights</h3>
            <div className="space-y-4">
              <div className="border-l-4 border-red-500 pl-4">
                <h4 className="font-medium text-gray-900">High Risk Activity Detected</h4>
                <p className="text-sm text-gray-600 mt-1">
                  User 'rbrown' shows unusual data access patterns with 500MB downloaded in 10 minutes. 
                  This represents a 400% increase from baseline behavior.
                </p>
                <p className="text-xs text-gray-500 mt-2">Recommendation: Immediate investigation required</p>
              </div>
              
              <div className="border-l-4 border-orange-500 pl-4">
                <h4 className="font-medium text-gray-900">Off-Hours Access Increase</h4>
                <p className="text-sm text-gray-600 mt-1">
                  15% increase in after-hours system access detected across multiple users. 
                  Most activity concentrated between 2:00 AM - 4:00 AM.
                </p>
                <p className="text-xs text-gray-500 mt-2">Recommendation: Review access policies and implement additional monitoring</p>
              </div>
              
              <div className="border-l-4 border-yellow-500 pl-4">
                <h4 className="font-medium text-gray-900">Geographic Anomalies</h4>
                <p className="text-sm text-gray-600 mt-1">
                  Multiple users showing login attempts from new geographic locations. 
                  Possible VPN usage or compromised credentials.
                </p>
                <p className="text-xs text-gray-500 mt-2">Recommendation: Implement geo-fencing and multi-factor authentication</p>
              </div>
              
              <div className="border-l-4 border-green-500 pl-4">
                <h4 className="font-medium text-gray-900">Improved Security Posture</h4>
                <p className="text-sm text-gray-600 mt-1">
                  Failed login attempts decreased by 3% this week. 
                  User security awareness training showing positive results.
                </p>
                <p className="text-xs text-gray-500 mt-2">Recommendation: Continue current security training program</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Trending Behaviors</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Mobile Device Usage</span>
                  <span className="text-sm font-medium text-green-600">↑ 22%</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Cloud Storage Access</span>
                  <span className="text-sm font-medium text-blue-600">↑ 18%</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">VPN Connections</span>
                  <span className="text-sm font-medium text-orange-600">↑ 35%</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Email Attachments</span>
                  <span className="text-sm font-medium text-red-600">↓ 12%</span>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Recommendations</h3>
              <div className="space-y-3">
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Implement Data Loss Prevention</p>
                    <p className="text-xs text-gray-500">High priority - Large data transfers detected</p>
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Enhanced MFA for High-Risk Users</p>
                    <p className="text-xs text-gray-500">Medium priority - Unusual access patterns</p>
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Update Access Policies</p>
                    <p className="text-xs text-gray-500">Low priority - Policy review needed</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default UserBehaviorAnalytics
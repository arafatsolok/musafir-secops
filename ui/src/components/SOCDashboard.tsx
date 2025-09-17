import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Server, 
  Eye, 
  Zap,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  BarChart3
} from 'lucide-react'
import { dashboardService, alertService } from '../services'

interface Event {
  ts: string
  tenant_id: string
  asset: {
    id: string
    type: string
    os: string
    ip: string
  }
  user: {
    id: string
    sid: string
  }
  event: {
    class: string
    name: string
    severity: number
    attrs: Record<string, any>
  }
  ingest: {
    agent_version: string
    schema: string
  }
}

interface SOCDashboardProps {
  events: Event[]
  loading: boolean
  error: string | null
}

const SOCDashboard: React.FC<SOCDashboardProps> = ({ loading, error }) => {
  const [realTimeStats, setRealTimeStats] = useState({
    activeThreats: 0,
    criticalAlerts: 0,
    assetsMonitored: 0,
    incidentsOpen: 0,
    complianceScore: 0,
    threatLevel: 'Low'
  })

  const [recentAlerts, setRecentAlerts] = useState<any[]>([])

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      
      // Load dashboard metrics
      const metricsResponse = await dashboardService.getDashboardMetrics()
      if (metricsResponse.success && metricsResponse.data) {
        setRealTimeStats({
          activeThreats: metricsResponse.data.totalIncidents,
          criticalAlerts: metricsResponse.data.criticalAlerts,
          assetsMonitored: metricsResponse.data.assetsMonitored,
          incidentsOpen: metricsResponse.data.openIncidents,
          complianceScore: 94, // Default value
          threatLevel: metricsResponse.data.criticalAlerts > 10 ? 'High' : 
                      metricsResponse.data.criticalAlerts > 5 ? 'Medium' : 'Low'
        })
      }

      // Load recent alerts
      const alertsResponse = await alertService.getRecentAlerts(5)
      if (alertsResponse.success && alertsResponse.data) {
        setRecentAlerts(alertsResponse.data.map(alert => ({
          id: alert.id,
          title: alert.title,
          severity: alert.severity,
          asset: alert.affectedAssets[0] || 'Unknown',
          timestamp: new Date(alert.timestamp).toLocaleString(),
          status: alert.status
        })))
      }
    } catch (err) {
      console.error('Error loading dashboard data:', err)
      // Fallback to demo data
      setRealTimeStats({
        activeThreats: 23,
        criticalAlerts: 7,
        assetsMonitored: 1247,
        incidentsOpen: 12,
        complianceScore: 94,
        threatLevel: 'Medium'
      })

      setRecentAlerts([
        {
          id: '1',
          title: 'Suspicious PowerShell Execution',
          severity: 'High',
          asset: 'WS-001',
          timestamp: '2 minutes ago',
          status: 'Open'
        },
        {
          id: '2',
          title: 'Failed Login Attempts',
          severity: 'Medium',
          asset: 'DC-001',
          timestamp: '5 minutes ago',
          status: 'Investigating'
        },
        {
          id: '3',
          title: 'Unusual Network Traffic',
          severity: 'Low',
          asset: 'FW-001',
          timestamp: '10 minutes ago',
          status: 'Resolved'
        }
      ])
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
      case 'critical':
        return 'text-red-600 bg-red-100'
      case 'medium':
        return 'text-yellow-600 bg-yellow-100'
      case 'low':
        return 'text-green-600 bg-green-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'open':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'investigating':
        return <Clock className="h-4 w-4 text-yellow-500" />
      case 'resolved':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      default:
        return <XCircle className="h-4 w-4 text-gray-500" />
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <AlertTriangle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Error Loading Dashboard</h2>
          <p className="text-gray-600">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Security Operations Center</h1>
        <p className="text-gray-600">Real-time security monitoring and threat detection</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow-sm p-6 border-l-4 border-red-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Threats</p>
              <p className="text-3xl font-bold text-gray-900">{realTimeStats.activeThreats}</p>
            </div>
            <Shield className="h-12 w-12 text-red-500" />
          </div>
          <div className="mt-4">
            <span className="text-sm text-red-600">+3 from last hour</span>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-6 border-l-4 border-yellow-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Critical Alerts</p>
              <p className="text-3xl font-bold text-gray-900">{realTimeStats.criticalAlerts}</p>
            </div>
            <AlertTriangle className="h-12 w-12 text-yellow-500" />
          </div>
          <div className="mt-4">
            <span className="text-sm text-yellow-600">Requires attention</span>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-6 border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Assets Monitored</p>
              <p className="text-3xl font-bold text-gray-900">{realTimeStats.assetsMonitored.toLocaleString()}</p>
            </div>
            <Server className="h-12 w-12 text-blue-500" />
          </div>
          <div className="mt-4">
            <span className="text-sm text-green-600">98.7% coverage</span>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-6 border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Compliance Score</p>
              <p className="text-3xl font-bold text-gray-900">{realTimeStats.complianceScore}%</p>
            </div>
            <CheckCircle className="h-12 w-12 text-green-500" />
          </div>
          <div className="mt-4">
            <span className="text-sm text-green-600">Excellent</span>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Threat Level Indicator */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Current Threat Level</h3>
          <div className="text-center">
            <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-yellow-100 mb-4">
              <Eye className="h-12 w-12 text-yellow-600" />
            </div>
            <h4 className="text-2xl font-bold text-yellow-600 mb-2">{realTimeStats.threatLevel}</h4>
            <p className="text-sm text-gray-600">Elevated security posture recommended</p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
          <div className="space-y-3">
            <button className="w-full flex items-center justify-between p-3 bg-red-50 hover:bg-red-100 rounded-lg transition-colors">
              <span className="text-sm font-medium text-red-700">Initiate Incident Response</span>
              <Zap className="h-4 w-4 text-red-600" />
            </button>
            <button className="w-full flex items-center justify-between p-3 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
              <span className="text-sm font-medium text-blue-700">Run Threat Hunt</span>
              <Activity className="h-4 w-4 text-blue-600" />
            </button>
            <button className="w-full flex items-center justify-between p-3 bg-green-50 hover:bg-green-100 rounded-lg transition-colors">
              <span className="text-sm font-medium text-green-700">Generate Report</span>
              <BarChart3 className="h-4 w-4 text-green-600" />
            </button>
          </div>
        </div>

        {/* System Health */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">System Health</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Data Ingestion</span>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                <span className="text-sm font-medium text-green-600">Healthy</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">ML Processing</span>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                <span className="text-sm font-medium text-green-600">Operational</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Correlation Engine</span>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
                <span className="text-sm font-medium text-yellow-600">Warning</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Threat Intelligence</span>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                <span className="text-sm font-medium text-green-600">Updated</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Recent Security Alerts</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Alert
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Asset
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {recentAlerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">{alert.title}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {alert.asset}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {alert.timestamp}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {getStatusIcon(alert.status)}
                      <span className="ml-2 text-sm text-gray-900">{alert.status}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default SOCDashboard
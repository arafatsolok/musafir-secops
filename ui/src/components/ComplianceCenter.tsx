import React, { useState, useEffect } from 'react'
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  FileText, 
  Download, 
  Calendar,
  BarChart3,
  Settings,
  Eye,
  Filter,
  Search,
  Clock,
  Users,
  Database,
  Lock,
  Zap,
  TrendingUp,
  AlertCircle
} from 'lucide-react'

interface ComplianceFramework {
  id: string
  name: string
  description: string
  controls: number
  compliant: number
  non_compliant: number
  pending: number
  last_assessment: string
}

interface ComplianceControl {
  id: string
  framework: string
  control_id: string
  title: string
  description: string
  status: 'compliant' | 'non_compliant' | 'pending' | 'not_applicable'
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  last_tested: string
  next_review: string
  owner: string
  evidence: string[]
}

interface AuditLog {
  id: string
  timestamp: string
  user: string
  action: string
  resource: string
  result: 'success' | 'failure'
  details: string
}

const ComplianceCenter: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'frameworks' | 'controls' | 'audit' | 'reports'>('overview')
  const [selectedFramework, setSelectedFramework] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')

  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([
    {
      id: 'iso27001',
      name: 'ISO 27001',
      description: 'Information Security Management System',
      controls: 114,
      compliant: 89,
      non_compliant: 15,
      pending: 10,
      last_assessment: '2024-01-10'
    },
    {
      id: 'nist',
      name: 'NIST Cybersecurity Framework',
      description: 'National Institute of Standards and Technology',
      controls: 108,
      compliant: 92,
      non_compliant: 8,
      pending: 8,
      last_assessment: '2024-01-12'
    },
    {
      id: 'sox',
      name: 'SOX',
      description: 'Sarbanes-Oxley Act',
      controls: 45,
      compliant: 41,
      non_compliant: 2,
      pending: 2,
      last_assessment: '2024-01-08'
    },
    {
      id: 'gdpr',
      name: 'GDPR',
      description: 'General Data Protection Regulation',
      controls: 32,
      compliant: 28,
      non_compliant: 3,
      pending: 1,
      last_assessment: '2024-01-14'
    }
  ])

  const [controls, setControls] = useState<ComplianceControl[]>([
    {
      id: '1',
      framework: 'iso27001',
      control_id: 'A.8.1.1',
      title: 'Inventory of assets',
      description: 'Assets associated with information and information processing facilities shall be identified',
      status: 'compliant',
      risk_level: 'medium',
      last_tested: '2024-01-10',
      next_review: '2024-04-10',
      owner: 'IT Security Team',
      evidence: ['Asset inventory report', 'Asset management policy']
    },
    {
      id: '2',
      framework: 'nist',
      control_id: 'ID.AM-1',
      title: 'Physical devices and systems',
      description: 'Physical devices and systems within the organization are inventoried',
      status: 'non_compliant',
      risk_level: 'high',
      last_tested: '2024-01-12',
      next_review: '2024-02-12',
      owner: 'Infrastructure Team',
      evidence: []
    },
    {
      id: '3',
      framework: 'sox',
      control_id: 'SOX-404',
      title: 'Management Assessment',
      description: 'Management assessment of internal control over financial reporting',
      status: 'compliant',
      risk_level: 'critical',
      last_tested: '2024-01-08',
      next_review: '2024-07-08',
      owner: 'Finance Team',
      evidence: ['Management assessment report', 'Control testing results']
    }
  ])

  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([
    {
      id: '1',
      timestamp: '2024-01-15 14:30:00',
      user: 'admin@company.com',
      action: 'LOGIN',
      resource: 'Compliance Dashboard',
      result: 'success',
      details: 'User logged in successfully'
    },
    {
      id: '2',
      timestamp: '2024-01-15 14:25:00',
      user: 'auditor@company.com',
      action: 'EXPORT_REPORT',
      resource: 'ISO 27001 Compliance Report',
      result: 'success',
      details: 'Compliance report exported to PDF'
    },
    {
      id: '3',
      timestamp: '2024-01-15 14:20:00',
      user: 'security@company.com',
      action: 'UPDATE_CONTROL',
      resource: 'Control A.8.1.1',
      result: 'success',
      details: 'Control status updated to compliant'
    }
  ])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'non_compliant':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'pending':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'not_applicable':
        return 'text-gray-700 bg-gray-100 border-gray-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical':
        return 'text-purple-700 bg-purple-100'
      case 'high':
        return 'text-red-700 bg-red-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-green-700 bg-green-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'non_compliant':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'pending':
        return <Clock className="h-5 w-5 text-yellow-500" />
      default:
        return <AlertTriangle className="h-5 w-5 text-gray-500" />
    }
  }

  const filteredControls = controls.filter(control => {
    const matchesFramework = selectedFramework === 'all' || control.framework === selectedFramework
    const matchesSearch = control.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         control.control_id.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesFramework && matchesSearch
  })

  const totalControls = frameworks.reduce((sum, fw) => sum + fw.controls, 0)
  const totalCompliant = frameworks.reduce((sum, fw) => sum + fw.compliant, 0)
  const totalNonCompliant = frameworks.reduce((sum, fw) => sum + fw.non_compliant, 0)
  const compliancePercentage = Math.round((totalCompliant / totalControls) * 100)

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Compliance Center</h1>
            <p className="text-gray-600">Monitor compliance across security frameworks and regulations</p>
          </div>
          <div className="flex space-x-3">
            <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
              <Download className="h-4 w-4" />
              <span>Export Report</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <Settings className="h-4 w-4" />
              <span>Settings</span>
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'frameworks', label: 'Frameworks', icon: Shield },
            { id: 'controls', label: 'Controls', icon: CheckCircle },
            { id: 'audit', label: 'Audit Trail', icon: FileText },
            { id: 'reports', label: 'Reports', icon: Download }
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
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <TrendingUp className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Overall Compliance</p>
                  <p className="text-2xl font-semibold text-gray-900">{compliancePercentage}%</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <CheckCircle className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Compliant Controls</p>
                  <p className="text-2xl font-semibold text-gray-900">{totalCompliant}</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <XCircle className="h-8 w-8 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Non-Compliant</p>
                  <p className="text-2xl font-semibold text-gray-900">{totalNonCompliant}</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Shield className="h-8 w-8 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Frameworks</p>
                  <p className="text-2xl font-semibold text-gray-900">{frameworks.length}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Framework Status */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Framework Compliance Status</h3>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                {frameworks.map((framework) => {
                  const compliance = Math.round((framework.compliant / framework.controls) * 100)
                  return (
                    <div key={framework.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <h4 className="font-medium text-gray-900">{framework.name}</h4>
                          <p className="text-sm text-gray-600">{framework.description}</p>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-semibold text-gray-900">{compliance}%</div>
                          <div className="text-sm text-gray-500">Compliant</div>
                        </div>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                        <div
                          className="bg-green-600 h-2 rounded-full"
                          style={{ width: `${compliance}%` }}
                        ></div>
                      </div>
                      <div className="flex justify-between text-sm text-gray-600">
                        <span>{framework.compliant} compliant</span>
                        <span>{framework.non_compliant} non-compliant</span>
                        <span>{framework.pending} pending</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Frameworks Tab */}
      {activeTab === 'frameworks' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {frameworks.map((framework) => (
            <div key={framework.id} className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">{framework.name}</h3>
                <Shield className="h-6 w-6 text-blue-600" />
              </div>
              <p className="text-gray-600 mb-4">{framework.description}</p>
              
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Total Controls</span>
                  <span className="text-sm font-medium text-gray-900">{framework.controls}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Compliant</span>
                  <span className="text-sm font-medium text-green-600">{framework.compliant}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Non-Compliant</span>
                  <span className="text-sm font-medium text-red-600">{framework.non_compliant}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-600">Pending</span>
                  <span className="text-sm font-medium text-yellow-600">{framework.pending}</span>
                </div>
              </div>
              
              <div className="mt-4 pt-4 border-t border-gray-200">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Last Assessment</span>
                  <span className="text-sm text-gray-900">{new Date(framework.last_assessment).toLocaleDateString()}</span>
                </div>
              </div>
              
              <button className="w-full mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                View Details
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Controls Tab */}
      {activeTab === 'controls' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white rounded-lg shadow-sm p-4">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search controls..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              <select
                value={selectedFramework}
                onChange={(e) => setSelectedFramework(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Frameworks</option>
                {frameworks.map((fw) => (
                  <option key={fw.id} value={fw.id}>{fw.name}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Controls List */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Compliance Controls</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {filteredControls.map((control) => (
                <div key={control.id} className="p-6">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start space-x-3">
                      {getStatusIcon(control.status)}
                      <div>
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-medium text-gray-900">{control.control_id}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskColor(control.risk_level)}`}>
                            {control.risk_level.toUpperCase()}
                          </span>
                        </div>
                        <h5 className="text-sm font-medium text-gray-900 mb-1">{control.title}</h5>
                        <p className="text-sm text-gray-600">{control.description}</p>
                      </div>
                    </div>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(control.status)}`}>
                      {control.status.replace('_', ' ').toUpperCase()}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-sm text-gray-600">
                    <div>
                      <span className="font-medium">Owner:</span> {control.owner}
                    </div>
                    <div>
                      <span className="font-medium">Last Tested:</span> {new Date(control.last_tested).toLocaleDateString()}
                    </div>
                    <div>
                      <span className="font-medium">Next Review:</span> {new Date(control.next_review).toLocaleDateString()}
                    </div>
                  </div>
                  
                  {control.evidence.length > 0 && (
                    <div className="mt-3">
                      <span className="text-sm font-medium text-gray-700">Evidence:</span>
                      <div className="flex flex-wrap gap-2 mt-1">
                        {control.evidence.map((evidence, index) => (
                          <span key={index} className="inline-flex px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded">
                            {evidence}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Audit Trail Tab */}
      {activeTab === 'audit' && (
        <div className="bg-white rounded-lg shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Audit Trail</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {auditLogs.map((log) => (
              <div key={log.id} className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${log.result === 'success' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-gray-900">{log.action}</span>
                        <span className="text-gray-500">by</span>
                        <span className="text-gray-900">{log.user}</span>
                      </div>
                      <div className="text-sm text-gray-600 mt-1">
                        Resource: {log.resource}
                      </div>
                      <div className="text-sm text-gray-500 mt-1">
                        {log.details}
                      </div>
                    </div>
                  </div>
                  <div className="text-sm text-gray-500">
                    {new Date(log.timestamp).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {frameworks.map((framework) => (
              <div key={framework.id} className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">{framework.name} Report</h3>
                  <FileText className="h-6 w-6 text-blue-600" />
                </div>
                <p className="text-gray-600 mb-4">Comprehensive compliance report for {framework.name}</p>
                
                <div className="space-y-2 mb-4">
                  <div className="flex justify-between text-sm">
                    <span>Compliance Rate:</span>
                    <span className="font-medium">{Math.round((framework.compliant / framework.controls) * 100)}%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Last Updated:</span>
                    <span>{new Date(framework.last_assessment).toLocaleDateString()}</span>
                  </div>
                </div>
                
                <button className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  <Download className="h-4 w-4" />
                  <span>Download PDF</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default ComplianceCenter
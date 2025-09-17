import React, { useState, useEffect } from 'react'
import { 
  Monitor, 
  Smartphone, 
  Server, 
  Wifi, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  XCircle,
  Search,
  Upload,
  RefreshCw,
  Eye,
  Edit,
  Plus,
  HardDrive,
  Network,
  Lock,
  Unlock,
  Activity
} from 'lucide-react'
import { assetService, Asset as ApiAsset } from '../services'

interface Asset {
  id: string
  name: string
  type: 'workstation' | 'server' | 'mobile' | 'network' | 'iot' | 'virtual'
  ip_address: string
  mac_address: string
  os: string
  os_version: string
  location: string
  owner: string
  department: string
  criticality: 'critical' | 'high' | 'medium' | 'low'
  status: 'online' | 'offline' | 'maintenance' | 'decommissioned'
  last_seen: string
  agent_status: 'installed' | 'not_installed' | 'outdated' | 'error'
  vulnerabilities: {
    critical: number
    high: number
    medium: number
    low: number
  }
  compliance_score: number
  patch_level: 'current' | 'outdated' | 'critical'
  encryption_status: 'encrypted' | 'partial' | 'unencrypted'
  backup_status: 'current' | 'outdated' | 'none'
}

interface NetworkSegment {
  id: string
  name: string
  subnet: string
  vlan: string
  security_zone: 'dmz' | 'internal' | 'guest' | 'management'
  asset_count: number
  risk_level: 'low' | 'medium' | 'high' | 'critical'
}

interface Vulnerability {
  id: string
  cve_id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss_score: number
  affected_assets: number
  published_date: string
  patch_available: boolean
  exploited_in_wild: boolean
}

const AssetInventory: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'assets' | 'network' | 'vulnerabilities' | 'compliance'>('assets')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedType, setSelectedType] = useState<string>('all')
  const [selectedStatus, setSelectedStatus] = useState<string>('all')
  const [selectedCriticality, setSelectedCriticality] = useState<string>('all')
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadAssets()
  }, [])

  const loadAssets = async () => {
    try {
      setLoading(true)
      const response = await assetService.getAssets()
      
      if (response.success && response.data) {
        // Transform API data to match local Asset interface
        const transformedAssets: Asset[] = response.data.map((apiAsset: ApiAsset) => ({
          id: apiAsset.id,
          name: apiAsset.name,
          type: apiAsset.type === 'network_device' ? 'network' : 
                apiAsset.type === 'cloud_resource' ? 'virtual' : 
                apiAsset.type as 'workstation' | 'server' | 'mobile' | 'iot',
          ip_address: apiAsset.ip,
          mac_address: '', // Not available in API, use empty string
          os: apiAsset.os,
          os_version: '', // Not available in API, use empty string
          location: apiAsset.location,
          owner: apiAsset.owner,
          department: '', // Not available in API, use empty string
          criticality: apiAsset.criticality,
          status: apiAsset.status,
          last_seen: apiAsset.lastSeen,
          agent_status: 'not_installed' as const, // Default value
          vulnerabilities: {
            critical: 0,
            high: 0,
            medium: 0,
            low: typeof apiAsset.vulnerabilities === 'number' ? apiAsset.vulnerabilities : 0
          },
          compliance_score: 85, // Default value
          patch_level: 'current' as const, // Default value
          encryption_status: 'encrypted' as const, // Default value
          backup_status: 'current' as const // Default value
        }))
        setAssets(transformedAssets)
      } else {
        // Fallback to demo data if API is not available
        setAssets([
          {
            id: '1',
            name: 'WS-001-FINANCE',
            type: 'workstation',
            ip_address: '192.168.1.101',
            mac_address: '00:1B:44:11:3A:B7',
            os: 'Windows 11',
            os_version: '22H2',
            location: 'Building A - Floor 3',
            owner: 'John Smith',
            department: 'Finance',
            criticality: 'high',
            status: 'online',
            last_seen: '2024-01-15T16:30:00Z',
            agent_status: 'installed',
            vulnerabilities: {
              critical: 2,
              high: 5,
              medium: 6,
              low: 2
            },
            compliance_score: 85,
            patch_level: 'current',
            encryption_status: 'encrypted',
            backup_status: 'current'
          },
          {
            id: '2',
            name: 'SRV-001-DC',
            type: 'server',
            ip_address: '192.168.1.10',
            mac_address: '00:1B:44:11:3A:B8',
            os: 'Windows Server 2022',
            os_version: '21H2',
            location: 'Data Center - Rack 1',
            owner: 'IT Team',
            department: 'IT',
            criticality: 'critical',
            status: 'online',
            last_seen: '2024-01-15T16:35:00Z',
            agent_status: 'installed',
            vulnerabilities: {
              critical: 1,
              high: 2,
              medium: 2,
              low: 1
            },
            compliance_score: 92,
            patch_level: 'current',
            encryption_status: 'encrypted',
            backup_status: 'current'
          },
          {
            id: '3',
            name: 'MOB-001-CEO',
            type: 'mobile',
            ip_address: '192.168.1.205',
            mac_address: '00:1B:44:11:3A:B9',
            os: 'iOS 17.2',
            os_version: '17.2.1',
            location: 'Executive Office',
            owner: 'Jane Doe',
            department: 'Executive',
            criticality: 'critical',
            status: 'online',
            last_seen: '2024-01-15T16:25:00Z',
            agent_status: 'not_installed',
            vulnerabilities: {
              critical: 0,
              high: 1,
              medium: 1,
              low: 1
            },
            compliance_score: 78,
            patch_level: 'outdated',
            encryption_status: 'encrypted',
            backup_status: 'none'
          }
        ])
      }
    } catch (err) {
      setError('Failed to load assets')
      console.error('Error loading assets:', err)
    } finally {
      setLoading(false);
    }
  };

  const [networkSegments] = useState<NetworkSegment[]>([
    {
      id: '1',
      name: 'Corporate Network',
      subnet: '192.168.1.0/24',
      vlan: 'VLAN 10',
      security_zone: 'internal',
      asset_count: 156,
      risk_level: 'medium'
    },
    {
      id: '2',
      name: 'DMZ',
      subnet: '10.0.1.0/24',
      vlan: 'VLAN 20',
      security_zone: 'dmz',
      asset_count: 12,
      risk_level: 'high'
    },
    {
      id: '3',
      name: 'Guest Network',
      subnet: '172.16.1.0/24',
      vlan: 'VLAN 30',
      security_zone: 'guest',
      asset_count: 45,
      risk_level: 'low'
    },
    {
      id: '4',
      name: 'Management Network',
      subnet: '192.168.100.0/24',
      vlan: 'VLAN 100',
      security_zone: 'management',
      asset_count: 8,
      risk_level: 'critical'
    }
  ])

  const [vulnerabilities] = useState<Vulnerability[]>([
    {
      id: '1',
      cve_id: 'CVE-2024-0001',
      title: 'Windows Kernel Privilege Escalation',
      severity: 'critical',
      cvss_score: 9.8,
      affected_assets: 45,
      published_date: '2024-01-10',
      patch_available: true,
      exploited_in_wild: true
    },
    {
      id: '2',
      cve_id: 'CVE-2024-0002',
      title: 'Apache HTTP Server Buffer Overflow',
      severity: 'high',
      cvss_score: 7.5,
      affected_assets: 12,
      published_date: '2024-01-08',
      patch_available: true,
      exploited_in_wild: false
    },
    {
      id: '3',
      cve_id: 'CVE-2024-0003',
      title: 'Chrome V8 Engine Memory Corruption',
      severity: 'high',
      cvss_score: 8.1,
      affected_assets: 89,
      published_date: '2024-01-12',
      patch_available: true,
      exploited_in_wild: false
    }
  ])

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'workstation':
        return <Monitor className="h-5 w-5 text-blue-600" />
      case 'server':
        return <Server className="h-5 w-5 text-green-600" />
      case 'mobile':
        return <Smartphone className="h-5 w-5 text-purple-600" />
      case 'network':
        return <Wifi className="h-5 w-5 text-orange-600" />
      case 'iot':
        return <Activity className="h-5 w-5 text-red-600" />
      case 'virtual':
        return <HardDrive className="h-5 w-5 text-gray-600" />
      default:
        return <Monitor className="h-5 w-5 text-gray-600" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'offline':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'maintenance':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'decommissioned':
        return 'text-gray-700 bg-gray-100 border-gray-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getCriticalityColor = (criticality: string) => {
    switch (criticality) {
      case 'critical':
        return 'text-red-700 bg-red-100'
      case 'high':
        return 'text-orange-700 bg-orange-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-green-700 bg-green-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const getAgentStatusIcon = (status: string) => {
    switch (status) {
      case 'installed':
        return <CheckCircle className="h-4 w-4 text-green-600" />
      case 'not_installed':
        return <XCircle className="h-4 w-4 text-red-600" />
      case 'outdated':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />
      case 'error':
        return <XCircle className="h-4 w-4 text-red-600" />
      default:
        return <XCircle className="h-4 w-4 text-gray-600" />
    }
  }

  const getEncryptionIcon = (status: string) => {
    switch (status) {
      case 'encrypted':
        return <Lock className="h-4 w-4 text-green-600" />
      case 'partial':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />
      case 'unencrypted':
        return <Unlock className="h-4 w-4 text-red-600" />
      default:
        return <Unlock className="h-4 w-4 text-gray-600" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-700 bg-red-100'
      case 'high':
        return 'text-orange-700 bg-orange-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-green-700 bg-green-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'text-red-700 bg-red-100'
      case 'high':
        return 'text-orange-700 bg-orange-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-green-700 bg-green-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const filteredAssets = assets.filter(asset => {
    const matchesSearch = asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         asset.ip_address.includes(searchTerm) ||
                         asset.owner.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = selectedType === 'all' || asset.type === selectedType
    const matchesStatus = selectedStatus === 'all' || asset.status === selectedStatus
    const matchesCriticality = selectedCriticality === 'all' || asset.criticality === selectedCriticality
    return matchesSearch && matchesType && matchesStatus && matchesCriticality
  })

  const totalAssets = assets.length
  const onlineAssets = assets.filter(a => a.status === 'online').length
  const criticalVulns = assets.reduce((sum, asset) => {
    const vulns = asset.vulnerabilities
    return sum + (vulns ? vulns.critical + vulns.high + vulns.medium + vulns.low : 0)
  }, 0)
  const avgCompliance = assets.length > 0 ? Math.round(assets.reduce((sum, asset) => sum + (asset.compliance_score || 85), 0) / assets.length) : 0

  if (loading) {
    return (
      <div className="p-6 bg-gray-50 min-h-full">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <RefreshCw className="h-8 w-8 text-blue-600 animate-spin mx-auto mb-4" />
            <p className="text-gray-600">Loading assets...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 bg-gray-50 min-h-full">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <AlertTriangle className="h-8 w-8 text-red-600 mx-auto mb-4" />
            <p className="text-red-600 mb-2">Error loading assets</p>
            <p className="text-gray-600 text-sm">{error}</p>
            <button 
              onClick={loadAssets}
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Asset Inventory</h1>
            <p className="text-gray-600">Comprehensive asset management and security monitoring</p>
          </div>
          <div className="flex space-x-3">
            <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
              <Plus className="h-4 w-4" />
              <span>Add Asset</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <Upload className="h-4 w-4" />
              <span>Import</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <RefreshCw className="h-4 w-4" />
              <span>Scan</span>
            </button>
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Monitor className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Assets</p>
              <p className="text-2xl font-semibold text-gray-900">{totalAssets}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Online</p>
              <p className="text-2xl font-semibold text-gray-900">{onlineAssets}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertTriangle className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Critical Vulns</p>
              <p className="text-2xl font-semibold text-gray-900">{criticalVulns}</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Shield className="h-8 w-8 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Avg Compliance</p>
              <p className="text-2xl font-semibold text-gray-900">{avgCompliance}%</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'assets', label: 'Assets', icon: Monitor },
            { id: 'network', label: 'Network', icon: Network },
            { id: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
            { id: 'compliance', label: 'Compliance', icon: Shield }
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

      {/* Assets Tab */}
      {activeTab === 'assets' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white rounded-lg shadow-sm p-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search assets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Types</option>
                <option value="workstation">Workstation</option>
                <option value="server">Server</option>
                <option value="mobile">Mobile</option>
                <option value="network">Network</option>
                <option value="iot">IoT</option>
                <option value="virtual">Virtual</option>
              </select>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Status</option>
                <option value="online">Online</option>
                <option value="offline">Offline</option>
                <option value="maintenance">Maintenance</option>
                <option value="decommissioned">Decommissioned</option>
              </select>
              <select
                value={selectedCriticality}
                onChange={(e) => setSelectedCriticality(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Criticality</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {/* Assets List */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Assets ({filteredAssets.length})</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {filteredAssets.map((asset) => (
                <div key={asset.id} className="p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(asset.type)}
                      <div>
                        <h4 className="font-medium text-gray-900">{asset.name}</h4>
                        <p className="text-sm text-gray-600">{asset.ip_address} • {asset.mac_address}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(asset.status)}`}>
                        {asset.status.toUpperCase()}
                      </span>
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getCriticalityColor(asset.criticality)}`}>
                        {asset.criticality.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-6 gap-4 mb-4">
                    <div>
                      <span className="text-xs font-medium text-gray-500">OS</span>
                      <p className="text-sm text-gray-900">{asset.os} {asset.os_version}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Owner</span>
                      <p className="text-sm text-gray-900">{asset.owner}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Department</span>
                      <p className="text-sm text-gray-900">{asset.department}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Location</span>
                      <p className="text-sm text-gray-900">{asset.location}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Last Seen</span>
                      <p className="text-sm text-gray-900">{new Date(asset.last_seen).toLocaleString()}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-gray-500">Compliance</span>
                      <p className="text-sm text-gray-900">{asset.compliance_score}%</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-6">
                      <div className="flex items-center space-x-1">
                        {getAgentStatusIcon(asset.agent_status)}
                        <span className="text-xs text-gray-600">Agent</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        {getEncryptionIcon(asset.encryption_status)}
                        <span className="text-xs text-gray-600">Encryption</span>
                      </div>
                      <div className="flex items-center space-x-2 text-xs text-gray-600">
                        <span className="text-red-600 font-medium">{asset.vulnerabilities.critical}</span>
                        <span className="text-orange-600 font-medium">{asset.vulnerabilities.high}</span>
                        <span className="text-yellow-600 font-medium">{asset.vulnerabilities.medium}</span>
                        <span className="text-green-600 font-medium">{asset.vulnerabilities.low}</span>
                        <span>Vulnerabilities</span>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-800">
                        <Eye className="h-4 w-4" />
                      </button>
                      <button className="text-gray-600 hover:text-gray-800">
                        <Edit className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Network Tab */}
      {activeTab === 'network' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {networkSegments.map((segment) => (
              <div key={segment.id} className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <Network className="h-6 w-6 text-blue-600" />
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">{segment.name}</h3>
                      <p className="text-sm text-gray-600">{segment.subnet} • {segment.vlan}</p>
                    </div>
                  </div>
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(segment.risk_level)}`}>
                    {segment.risk_level.toUpperCase()}
                  </span>
                </div>
                
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Security Zone:</span>
                    <span className="font-medium text-gray-900 capitalize">{segment.security_zone}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Assets:</span>
                    <span className="font-medium text-gray-900">{segment.asset_count}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Risk Level:</span>
                    <span className={`font-medium capitalize ${
                      segment.risk_level === 'critical' ? 'text-red-600' :
                      segment.risk_level === 'high' ? 'text-orange-600' :
                      segment.risk_level === 'medium' ? 'text-yellow-600' :
                      'text-green-600'
                    }`}>
                      {segment.risk_level}
                    </span>
                  </div>
                </div>
                
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <button className="w-full text-center text-blue-600 hover:text-blue-800 text-sm font-medium">
                    View Assets in Segment
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Critical Vulnerabilities</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="p-6">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <AlertTriangle className={`h-6 w-6 ${
                        vuln.severity === 'critical' ? 'text-red-600' :
                        vuln.severity === 'high' ? 'text-orange-600' :
                        vuln.severity === 'medium' ? 'text-yellow-600' :
                        'text-green-600'
                      }`} />
                      <div>
                        <h4 className="font-medium text-gray-900">{vuln.title}</h4>
                        <p className="text-sm text-gray-600">{vuln.cve_id}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className="text-sm font-medium text-gray-900">CVSS {vuln.cvss_score}</span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-gray-600">
                    <div>
                      <span className="font-medium">Affected Assets:</span> {vuln.affected_assets}
                    </div>
                    <div>
                      <span className="font-medium">Published:</span> {new Date(vuln.published_date).toLocaleDateString()}
                    </div>
                    <div>
                      <span className="font-medium">Patch Available:</span> 
                      <span className={vuln.patch_available ? 'text-green-600' : 'text-red-600'}>
                        {vuln.patch_available ? ' Yes' : ' No'}
                      </span>
                    </div>
                    <div>
                      <span className="font-medium">Exploited:</span>
                      <span className={vuln.exploited_in_wild ? 'text-red-600' : 'text-green-600'}>
                        {vuln.exploited_in_wild ? ' Yes' : ' No'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Overview</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Encryption</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-green-600 h-2 rounded-full" style={{ width: '85%' }}></div>
                    </div>
                    <span className="text-sm font-medium">85%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Patch Management</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-yellow-600 h-2 rounded-full" style={{ width: '72%' }}></div>
                    </div>
                    <span className="text-sm font-medium">72%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Agent Coverage</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-blue-600 h-2 rounded-full" style={{ width: '92%' }}></div>
                    </div>
                    <span className="text-sm font-medium">92%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Backup Status</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-green-600 h-2 rounded-full" style={{ width: '88%' }}></div>
                    </div>
                    <span className="text-sm font-medium">88%</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Critical Risk</span>
                  <span className="text-sm font-medium text-red-600">12 assets</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">High Risk</span>
                  <span className="text-sm font-medium text-orange-600">28 assets</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Medium Risk</span>
                  <span className="text-sm font-medium text-yellow-600">45 assets</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Low Risk</span>
                  <span className="text-sm font-medium text-green-600">89 assets</span>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recommendations</h3>
              <div className="space-y-3">
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Patch Critical Vulnerabilities</p>
                    <p className="text-xs text-gray-500">12 assets need immediate attention</p>
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Update Agent Software</p>
                    <p className="text-xs text-gray-500">8 agents are outdated</p>
                  </div>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Enable Encryption</p>
                    <p className="text-xs text-gray-500">15 assets need encryption</p>
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

export default AssetInventory
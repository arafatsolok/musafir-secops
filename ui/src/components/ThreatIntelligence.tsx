import React, { useState } from 'react'
import { 
  Shield, 
  Globe, 
  Eye, 
  Upload,
  Search,
  TrendingUp,
  Clock,
  Hash,
  Users,
  Database,
  Network,
  FileText,
  ExternalLink,
  RefreshCw
} from 'lucide-react'

interface ThreatFeed {
  id: string
  name: string
  provider: string
  type: 'commercial' | 'open_source' | 'government' | 'internal'
  status: 'active' | 'inactive' | 'error'
  last_updated: string
  ioc_count: number
  confidence: number
}

interface IOC {
  id: string
  value: string
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'file'
  threat_type: string
  confidence: number
  first_seen: string
  last_seen: string
  source: string
  tags: string[]
  description: string
  tlp: 'white' | 'green' | 'amber' | 'red'
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  description: string
  motivation: string
  sophistication: 'low' | 'medium' | 'high' | 'expert'
  origin_country: string
  first_seen: string
  last_activity: string
  associated_campaigns: string[]
  ttps: string[]
}

interface Campaign {
  id: string
  name: string
  description: string
  threat_actor: string
  start_date: string
  end_date?: string
  status: 'active' | 'inactive' | 'monitoring'
  targets: string[]
  techniques: string[]
  iocs: string[]
}

const ThreatIntelligence: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'feeds' | 'iocs' | 'actors' | 'campaigns' | 'analysis'>('feeds')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTLP, setSelectedTLP] = useState<string>('all')

  const [threatFeeds] = useState<ThreatFeed[]>([
    {
      id: '1',
      name: 'AlienVault OTX',
      provider: 'AT&T Cybersecurity',
      type: 'commercial',
      status: 'active',
      last_updated: '2024-01-15 15:30:00',
      ioc_count: 15420,
      confidence: 85
    },
    {
      id: '2',
      name: 'MISP Threat Sharing',
      provider: 'MISP Project',
      type: 'open_source',
      status: 'active',
      last_updated: '2024-01-15 14:45:00',
      ioc_count: 8932,
      confidence: 78
    },
    {
      id: '3',
      name: 'US-CERT Indicators',
      provider: 'CISA',
      type: 'government',
      status: 'active',
      last_updated: '2024-01-15 12:20:00',
      ioc_count: 2341,
      confidence: 92
    },
    {
      id: '4',
      name: 'Internal IOCs',
      provider: 'Security Team',
      type: 'internal',
      status: 'active',
      last_updated: '2024-01-15 16:10:00',
      ioc_count: 567,
      confidence: 95
    }
  ])

  const [iocs] = useState<IOC[]>([
    {
      id: '1',
      value: '192.168.1.100',
      type: 'ip',
      threat_type: 'C2 Server',
      confidence: 85,
      first_seen: '2024-01-10',
      last_seen: '2024-01-15',
      source: 'AlienVault OTX',
      tags: ['malware', 'c2', 'apt'],
      description: 'Command and control server associated with APT group',
      tlp: 'amber'
    },
    {
      id: '2',
      value: 'malicious-domain.com',
      type: 'domain',
      threat_type: 'Phishing',
      confidence: 92,
      first_seen: '2024-01-12',
      last_seen: '2024-01-15',
      source: 'US-CERT',
      tags: ['phishing', 'credential-theft'],
      description: 'Domain used in credential harvesting campaign',
      tlp: 'green'
    },
    {
      id: '3',
      value: 'a1b2c3d4e5f6789012345678901234567890abcd',
      type: 'hash',
      threat_type: 'Ransomware',
      confidence: 98,
      first_seen: '2024-01-14',
      last_seen: '2024-01-15',
      source: 'Internal IOCs',
      tags: ['ransomware', 'malware'],
      description: 'SHA-1 hash of ransomware payload',
      tlp: 'red'
    }
  ])

  const [threatActors] = useState<ThreatActor[]>([
    {
      id: '1',
      name: 'APT29',
      aliases: ['Cozy Bear', 'The Dukes'],
      description: 'Advanced persistent threat group attributed to Russian intelligence',
      motivation: 'Espionage',
      sophistication: 'expert',
      origin_country: 'Russia',
      first_seen: '2008-01-01',
      last_activity: '2024-01-10',
      associated_campaigns: ['SolarWinds', 'COVID-19 Research Targeting'],
      ttps: ['T1566.001', 'T1055', 'T1027']
    },
    {
      id: '2',
      name: 'Lazarus Group',
      aliases: ['Hidden Cobra', 'APT38'],
      description: 'North Korean state-sponsored threat group',
      motivation: 'Financial Gain',
      sophistication: 'high',
      origin_country: 'North Korea',
      first_seen: '2009-01-01',
      last_activity: '2024-01-08',
      associated_campaigns: ['WannaCry', 'SWIFT Banking Attacks'],
      ttps: ['T1566.002', 'T1059.003', 'T1105']
    }
  ])

  const [campaigns] = useState<Campaign[]>([
    {
      id: '1',
      name: 'Operation CloudHopper',
      description: 'Global campaign targeting managed service providers',
      threat_actor: 'APT10',
      start_date: '2024-01-01',
      status: 'active',
      targets: ['MSPs', 'Healthcare', 'Government'],
      techniques: ['T1566.001', 'T1055', 'T1027'],
      iocs: ['1', '2']
    },
    {
      id: '2',
      name: 'Ransomware Campaign 2024-01',
      description: 'Targeted ransomware attacks on critical infrastructure',
      threat_actor: 'Unknown',
      start_date: '2024-01-10',
      status: 'monitoring',
      targets: ['Energy', 'Transportation', 'Water'],
      techniques: ['T1566.002', 'T1059.001', 'T1486'],
      iocs: ['3']
    }
  ])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'inactive':
        return 'text-gray-700 bg-gray-100 border-gray-200'
      case 'error':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'monitoring':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getTLPColor = (tlp: string) => {
    switch (tlp) {
      case 'white':
        return 'text-gray-700 bg-white border-gray-300'
      case 'green':
        return 'text-green-700 bg-green-100 border-green-300'
      case 'amber':
        return 'text-yellow-700 bg-yellow-100 border-yellow-300'
      case 'red':
        return 'text-red-700 bg-red-100 border-red-300'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-300'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ip':
        return <Globe className="h-4 w-4 text-blue-600" />
      case 'domain':
        return <Network className="h-4 w-4 text-green-600" />
      case 'url':
        return <ExternalLink className="h-4 w-4 text-purple-600" />
      case 'hash':
        return <Hash className="h-4 w-4 text-orange-600" />
      case 'email':
        return <Users className="h-4 w-4 text-red-600" />
      case 'file':
        return <FileText className="h-4 w-4 text-gray-600" />
      default:
        return <Shield className="h-4 w-4 text-gray-600" />
    }
  }

  const getSophisticationColor = (level: string) => {
    switch (level) {
      case 'expert':
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

  const filteredIOCs = iocs.filter(ioc => {
    const matchesSearch = ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         ioc.threat_type.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesTLP = selectedTLP === 'all' || ioc.tlp === selectedTLP
    return matchesSearch && matchesTLP
  })

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Threat Intelligence</h1>
            <p className="text-gray-600">Monitor threat landscape and manage intelligence feeds</p>
          </div>
          <div className="flex space-x-3">
            <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
              <Upload className="h-4 w-4" />
              <span>Import IOCs</span>
            </button>
            <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
              <RefreshCw className="h-4 w-4" />
              <span>Sync Feeds</span>
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'feeds', label: 'Threat Feeds', icon: Database },
            { id: 'iocs', label: 'Indicators', icon: Shield },
            { id: 'actors', label: 'Threat Actors', icon: Users },
            { id: 'campaigns', label: 'Campaigns', icon: TrendingUp },
            { id: 'analysis', label: 'Analysis', icon: Eye }
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

      {/* Threat Feeds Tab */}
      {activeTab === 'feeds' && (
        <div className="space-y-6">
          {/* Feed Status Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Database className="h-8 w-8 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Active Feeds</p>
                  <p className="text-2xl font-semibold text-gray-900">{threatFeeds.filter(f => f.status === 'active').length}</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Shield className="h-8 w-8 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Total IOCs</p>
                  <p className="text-2xl font-semibold text-gray-900">{threatFeeds.reduce((sum, feed) => sum + feed.ioc_count, 0).toLocaleString()}</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <TrendingUp className="h-8 w-8 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Avg Confidence</p>
                  <p className="text-2xl font-semibold text-gray-900">{Math.round(threatFeeds.reduce((sum, feed) => sum + feed.confidence, 0) / threatFeeds.length)}%</p>
                </div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <Clock className="h-8 w-8 text-orange-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">Last Update</p>
                  <p className="text-sm font-semibold text-gray-900">2 min ago</p>
                </div>
              </div>
            </div>
          </div>

          {/* Feeds List */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Threat Intelligence Feeds</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {threatFeeds.map((feed) => (
                <div key={feed.id} className="p-6">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Database className="h-6 w-6 text-blue-600" />
                      <div>
                        <h4 className="font-medium text-gray-900">{feed.name}</h4>
                        <p className="text-sm text-gray-600">{feed.provider}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(feed.status)}`}>
                        {feed.status.toUpperCase()}
                      </span>
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        feed.type === 'commercial' ? 'text-blue-700 bg-blue-100' :
                        feed.type === 'government' ? 'text-purple-700 bg-purple-100' :
                        feed.type === 'internal' ? 'text-green-700 bg-green-100' :
                        'text-gray-700 bg-gray-100'
                      }`}>
                        {feed.type.replace('_', ' ').toUpperCase()}
                      </span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-gray-600">
                    <div>
                      <span className="font-medium">IOCs:</span> {feed.ioc_count.toLocaleString()}
                    </div>
                    <div>
                      <span className="font-medium">Confidence:</span> {feed.confidence}%
                    </div>
                    <div>
                      <span className="font-medium">Last Updated:</span> {new Date(feed.last_updated).toLocaleString()}
                    </div>
                    <div className="flex space-x-2">
                      <button className="text-blue-600 hover:text-blue-800">
                        <RefreshCw className="h-4 w-4" />
                      </button>
                      <button className="text-gray-600 hover:text-gray-800">
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

      {/* IOCs Tab */}
      {activeTab === 'iocs' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="bg-white rounded-lg shadow-sm p-4">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search indicators..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </div>
              <select
                value={selectedTLP}
                onChange={(e) => setSelectedTLP(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All TLP Levels</option>
                <option value="white">TLP:WHITE</option>
                <option value="green">TLP:GREEN</option>
                <option value="amber">TLP:AMBER</option>
                <option value="red">TLP:RED</option>
              </select>
            </div>
          </div>

          {/* IOCs List */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Indicators of Compromise</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {filteredIOCs.map((ioc) => (
                <div key={ioc.id} className="p-6">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start space-x-3">
                      {getTypeIcon(ioc.type)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-medium text-gray-900 font-mono text-sm">{ioc.value}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full border ${getTLPColor(ioc.tlp)}`}>
                            TLP:{ioc.tlp.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mb-1">{ioc.description}</p>
                        <div className="flex items-center space-x-4 text-xs text-gray-500">
                          <span>Type: {ioc.type.toUpperCase()}</span>
                          <span>Threat: {ioc.threat_type}</span>
                          <span>Confidence: {ioc.confidence}%</span>
                          <span>Source: {ioc.source}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${
                        ioc.confidence >= 80 ? 'bg-green-500' :
                        ioc.confidence >= 60 ? 'bg-yellow-500' :
                        'bg-red-500'
                      }`}></div>
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex flex-wrap gap-1">
                      {ioc.tags.map((tag, index) => (
                        <span key={index} className="inline-flex px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                    <div className="text-xs text-gray-500">
                      First: {new Date(ioc.first_seen).toLocaleDateString()} | Last: {new Date(ioc.last_seen).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Threat Actors Tab */}
      {activeTab === 'actors' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {threatActors.map((actor) => (
            <div key={actor.id} className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Users className="h-6 w-6 text-red-600" />
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{actor.name}</h3>
                    <p className="text-sm text-gray-600">
                      {actor.aliases.length > 0 && `AKA: ${actor.aliases.join(', ')}`}
                    </p>
                  </div>
                </div>
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSophisticationColor(actor.sophistication)}`}>
                  {actor.sophistication.toUpperCase()}
                </span>
              </div>
              
              <p className="text-gray-600 mb-4">{actor.description}</p>
              
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Motivation:</span>
                  <span className="font-medium text-gray-900">{actor.motivation}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Origin:</span>
                  <span className="font-medium text-gray-900">{actor.origin_country}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">First Seen:</span>
                  <span className="font-medium text-gray-900">{new Date(actor.first_seen).getFullYear()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Last Activity:</span>
                  <span className="font-medium text-gray-900">{new Date(actor.last_activity).toLocaleDateString()}</span>
                </div>
              </div>
              
              <div className="mt-4 pt-4 border-t border-gray-200">
                <div className="mb-2">
                  <span className="text-sm font-medium text-gray-700">Associated Campaigns:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {actor.associated_campaigns.map((campaign, index) => (
                      <span key={index} className="inline-flex px-2 py-1 text-xs bg-red-100 text-red-700 rounded">
                        {campaign}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-700">TTPs:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {actor.ttps.map((ttp, index) => (
                      <span key={index} className="inline-flex px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded">
                        {ttp}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Campaigns Tab */}
      {activeTab === 'campaigns' && (
        <div className="space-y-6">
          {campaigns.map((campaign) => (
            <div key={campaign.id} className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{campaign.name}</h3>
                  <p className="text-sm text-gray-600">Attributed to: {campaign.threat_actor}</p>
                </div>
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(campaign.status)}`}>
                  {campaign.status.toUpperCase()}
                </span>
              </div>
              
              <p className="text-gray-600 mb-4">{campaign.description}</p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div>
                  <span className="text-sm font-medium text-gray-700">Start Date:</span>
                  <p className="text-sm text-gray-900">{new Date(campaign.start_date).toLocaleDateString()}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-700">End Date:</span>
                  <p className="text-sm text-gray-900">{campaign.end_date ? new Date(campaign.end_date).toLocaleDateString() : 'Ongoing'}</p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-700">IOCs:</span>
                  <p className="text-sm text-gray-900">{campaign.iocs.length}</p>
                </div>
              </div>
              
              <div className="space-y-3">
                <div>
                  <span className="text-sm font-medium text-gray-700">Targets:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {campaign.targets.map((target, index) => (
                      <span key={index} className="inline-flex px-2 py-1 text-xs bg-orange-100 text-orange-700 rounded">
                        {target}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-700">Techniques:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {campaign.techniques.map((technique, index) => (
                      <span key={index} className="inline-flex px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded">
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Analysis Tab */}
      {activeTab === 'analysis' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Threat Landscape */}
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Landscape</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Malware</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-red-600 h-2 rounded-full" style={{ width: '75%' }}></div>
                    </div>
                    <span className="text-sm font-medium">75%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Phishing</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-orange-600 h-2 rounded-full" style={{ width: '60%' }}></div>
                    </div>
                    <span className="text-sm font-medium">60%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">C2 Infrastructure</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-yellow-600 h-2 rounded-full" style={{ width: '45%' }}></div>
                    </div>
                    <span className="text-sm font-medium">45%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">Ransomware</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-24 bg-gray-200 rounded-full h-2">
                      <div className="bg-purple-600 h-2 rounded-full" style={{ width: '30%' }}></div>
                    </div>
                    <span className="text-sm font-medium">30%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Intelligence */}
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Intelligence</h3>
              <div className="space-y-3">
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">New APT Campaign Detected</p>
                    <p className="text-xs text-gray-500">2 hours ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Phishing Domain Registered</p>
                    <p className="text-xs text-gray-500">4 hours ago</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">IOC Feed Updated</p>
                    <p className="text-xs text-gray-500">6 hours ago</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Intelligence Summary */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Intelligence Summary</h3>
            <div className="prose max-w-none text-gray-600">
              <p>
                Current threat landscape shows increased activity in ransomware campaigns targeting critical infrastructure. 
                APT groups are leveraging new techniques including supply chain attacks and zero-day exploits. 
                Phishing campaigns have evolved to use more sophisticated social engineering tactics.
              </p>
              <p className="mt-3">
                Recommended actions include updating threat hunting rules, reviewing email security policies, 
                and ensuring backup systems are properly isolated from production networks.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ThreatIntelligence
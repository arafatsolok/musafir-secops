import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Users, 
  Server, 
  Eye,
  Brain,
  Network,
  Zap,
  Target,
  BarChart3,
  PieChart,
  LineChart,
  Globe,
  Lock,
  Unlock,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react';

interface ThreatData {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  timestamp: string;
  source: string;
  target: string;
  confidence: number;
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
}

interface NetworkNode {
  id: string;
  label: string;
  type: 'user' | 'asset' | 'process' | 'file' | 'network';
  x: number;
  y: number;
  z: number;
  size: number;
  color: string;
  risk: number;
  connections: string[];
}

interface MLInsight {
  id: string;
  type: 'prediction' | 'anomaly' | 'trend' | 'recommendation';
  title: string;
  description: string;
  confidence: number;
  severity: string;
  entities: string[];
  recommendations: string[];
  timestamp: string;
}

interface GraphData {
  nodes: NetworkNode[];
  edges: Array<{
    source: string;
    target: string;
    type: string;
    weight: number;
  }>;
}

const AdvancedDashboard: React.FC = () => {
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [mlInsights, setMLInsights] = useState<MLInsight[]>([]);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });
  const [selectedView, setSelectedView] = useState<'overview' | 'threats' | 'network' | 'ml' | 'analytics'>('overview');
  const [isLoading, setIsLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [selectedThreat, setSelectedThreat] = useState<ThreatData | null>(null);
  const [is3DMode, setIs3DMode] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, [timeRange]);

  useEffect(() => {
    if (is3DMode && canvasRef.current) {
      initialize3DVisualization();
    }
  }, [is3DMode, graphData]);

  const fetchDashboardData = async () => {
    try {
      setIsLoading(true);
      
      // Fetch threats
      const threatsResponse = await fetch(`/api/threats?timeRange=${timeRange}`);
      const threatsData = await threatsResponse.json();
      setThreats(threatsData);

      // Fetch ML insights
      const mlResponse = await fetch(`/api/ml/insights?timeRange=${timeRange}`);
      const mlData = await mlResponse.json();
      setMLInsights(mlData);

      // Fetch network graph data
      const graphResponse = await fetch(`/api/graph/network?timeRange=${timeRange}`);
      const graphData = await graphResponse.json();
      setGraphData(graphData);

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const initialize3DVisualization = () => {
    // This would integrate with Three.js for 3D network visualization
    // For now, we'll create a placeholder
    if (canvasRef.current) {
      const canvas = canvasRef.current;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        // Draw 3D-like network visualization
        draw3DNetwork(ctx, graphData);
      }
    }
  };

  const draw3DNetwork = (ctx: CanvasRenderingContext2D, data: GraphData) => {
    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
    
    // Draw nodes
    data.nodes.forEach(node => {
      const x = node.x * ctx.canvas.width;
      const y = node.y * ctx.canvas.height;
      const size = node.size * 20;
      
      // Draw node with 3D effect
      ctx.beginPath();
      ctx.arc(x, y, size, 0, 2 * Math.PI);
      ctx.fillStyle = node.color;
      ctx.fill();
      
      // Add shadow for 3D effect
      ctx.shadowColor = 'rgba(0,0,0,0.3)';
      ctx.shadowBlur = 10;
      ctx.shadowOffsetX = 2;
      ctx.shadowOffsetY = 2;
      
      // Draw label
      ctx.fillStyle = '#333';
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, x, y - size - 5);
    });
    
    // Draw edges
    data.edges.forEach(edge => {
      const sourceNode = data.nodes.find(n => n.id === edge.source);
      const targetNode = data.nodes.find(n => n.id === edge.target);
      
      if (sourceNode && targetNode) {
        const x1 = sourceNode.x * ctx.canvas.width;
        const y1 = sourceNode.y * ctx.canvas.height;
        const x2 = targetNode.x * ctx.canvas.width;
        const y2 = targetNode.y * ctx.canvas.height;
        
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = `rgba(100, 100, 100, ${edge.weight})`;
        ctx.lineWidth = edge.weight * 3;
        ctx.stroke();
      }
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'investigating': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'resolved': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'false_positive': return <XCircle className="h-4 w-4 text-gray-500" />;
      default: return <AlertCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getMLInsightIcon = (type: string) => {
    switch (type) {
      case 'prediction': return <Brain className="h-5 w-5 text-blue-500" />;
      case 'anomaly': return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case 'trend': return <TrendingUp className="h-5 w-5 text-green-500" />;
      case 'recommendation': return <Target className="h-5 w-5 text-purple-500" />;
      default: return <Activity className="h-5 w-5 text-gray-500" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Advanced Security Dashboard</h1>
            <p className="mt-2 text-gray-600">Real-time threat detection and AI-powered insights</p>
          </div>
          <div className="flex items-center space-x-4">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <button
              onClick={() => setIs3DMode(!is3DMode)}
              className={`px-4 py-2 rounded-md font-medium ${
                is3DMode 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              {is3DMode ? '2D View' : '3D View'}
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="mb-8">
        <nav className="flex space-x-8">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'threats', label: 'Threats', icon: Shield },
            { id: 'network', label: 'Network', icon: Network },
            { id: 'ml', label: 'AI Insights', icon: Brain },
            { id: 'analytics', label: 'Analytics', icon: BarChart3 }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedView(tab.id as any)}
              className={`flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                selectedView === tab.id
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
              }`}
            >
              <tab.icon className="h-4 w-4 mr-2" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Overview Tab */}
      {selectedView === 'overview' && (
        <div className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <Shield className="h-6 w-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Threats</p>
                  <p className="text-2xl font-bold text-gray-900">{threats.filter(t => t.status === 'active').length}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <CheckCircle className="h-6 w-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Resolved</p>
                  <p className="text-2xl font-bold text-gray-900">{threats.filter(t => t.status === 'resolved').length}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Brain className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">AI Insights</p>
                  <p className="text-2xl font-bold text-gray-900">{mlInsights.length}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-lg shadow">
              <div className="flex items-center">
                <div className="p-2 bg-purple-100 rounded-lg">
                  <Network className="h-6 w-6 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Network Nodes</p>
                  <p className="text-2xl font-bold text-gray-900">{graphData.nodes.length}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Threats */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Recent Threats</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {threats.slice(0, 5).map((threat) => (
                <div key={threat.id} className="px-6 py-4 hover:bg-gray-50 cursor-pointer"
                     onClick={() => setSelectedThreat(threat)}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      {getStatusIcon(threat.status)}
                      <div className="ml-3">
                        <p className="text-sm font-medium text-gray-900">{threat.title}</p>
                        <p className="text-sm text-gray-500">{threat.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}
                      </span>
                      <span className="text-sm text-gray-500">{threat.timestamp}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Threats Tab */}
      {selectedView === 'threats' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Threat Intelligence</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Threat</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Confidence</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {threats.map((threat) => (
                    <tr key={threat.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">{threat.title}</div>
                          <div className="text-sm text-gray-500">{threat.description}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {getStatusIcon(threat.status)}
                          <span className="ml-2 text-sm text-gray-900">{threat.status}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="w-16 bg-gray-200 rounded-full h-2">
                            <div 
                              className="bg-blue-600 h-2 rounded-full" 
                              style={{ width: `${threat.confidence * 100}%` }}
                            ></div>
                          </div>
                          <span className="ml-2 text-sm text-gray-900">{Math.round(threat.confidence * 100)}%</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {threat.timestamp}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button className="text-blue-600 hover:text-blue-900">Investigate</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Network Tab */}
      {selectedView === 'network' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">Network Topology</h3>
            </div>
            <div className="p-6">
              {is3DMode ? (
                <div className="relative">
                  <canvas
                    ref={canvasRef}
                    width={800}
                    height={600}
                    className="border border-gray-300 rounded-lg"
                  />
                  <div className="absolute top-4 right-4 bg-white p-2 rounded shadow">
                    <p className="text-sm text-gray-600">3D Network View</p>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {graphData.nodes.map((node) => (
                    <div key={node.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">{node.label}</h4>
                          <p className="text-xs text-gray-500">{node.type}</p>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div 
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: node.color }}
                          ></div>
                          <span className="text-xs text-gray-500">Risk: {Math.round(node.risk * 100)}%</span>
                        </div>
                      </div>
                      <div className="mt-2">
                        <p className="text-xs text-gray-500">
                          Connections: {node.connections.length}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ML Insights Tab */}
      {selectedView === 'ml' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-medium text-gray-900">AI-Powered Insights</h3>
            </div>
            <div className="divide-y divide-gray-200">
              {mlInsights.map((insight) => (
                <div key={insight.id} className="px-6 py-4">
                  <div className="flex items-start">
                    <div className="flex-shrink-0">
                      {getMLInsightIcon(insight.type)}
                    </div>
                    <div className="ml-4 flex-1">
                      <div className="flex items-center justify-between">
                        <h4 className="text-sm font-medium text-gray-900">{insight.title}</h4>
                        <span className="text-xs text-gray-500">{insight.timestamp}</span>
                      </div>
                      <p className="mt-1 text-sm text-gray-600">{insight.description}</p>
                      <div className="mt-2 flex items-center space-x-4">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(insight.severity)}`}>
                          {insight.severity}
                        </span>
                        <span className="text-xs text-gray-500">
                          Confidence: {Math.round(insight.confidence * 100)}%
                        </span>
                      </div>
                      {insight.recommendations.length > 0 && (
                        <div className="mt-2">
                          <p className="text-xs font-medium text-gray-700">Recommendations:</p>
                          <ul className="mt-1 text-xs text-gray-600 list-disc list-inside">
                            {insight.recommendations.map((rec, index) => (
                              <li key={index}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Analytics Tab */}
      {selectedView === 'analytics' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Threat Trends</h3>
              <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
                <p className="text-gray-500">Chart visualization would go here</p>
              </div>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Risk Distribution</h3>
              <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
                <p className="text-gray-500">Pie chart visualization would go here</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900">{selectedThreat.title}</h3>
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <XCircle className="h-6 w-6" />
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">{selectedThreat.description}</p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm font-medium text-gray-700">Severity</p>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(selectedThreat.severity)}`}>
                      {selectedThreat.severity}
                    </span>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-700">Status</p>
                    <div className="flex items-center">
                      {getStatusIcon(selectedThreat.status)}
                      <span className="ml-2 text-sm text-gray-900">{selectedThreat.status}</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-700">Source</p>
                    <p className="text-sm text-gray-900">{selectedThreat.source}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-700">Target</p>
                    <p className="text-sm text-gray-900">{selectedThreat.target}</p>
                  </div>
                </div>
                <div className="pt-4 border-t">
                  <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                    Investigate Threat
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdvancedDashboard;

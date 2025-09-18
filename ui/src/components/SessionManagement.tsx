import React, { useState, useEffect } from 'react';
import {
  Users, Monitor, MapPin, Clock, Shield, AlertTriangle,
  Search, Filter, RefreshCw, LogOut, Eye, MoreVertical,
  Calendar, Globe, Smartphone, Laptop, Tablet, Server
} from 'lucide-react';
import { userService, UserSession, SessionActivity } from '../services/users';

interface SessionStats {
  totalActiveSessions: number;
  uniqueUsers: number;
  uniqueLocations: number;
  uniqueDevices: number;
  averageSessionDuration: number;
  highRiskSessions: number;
}

const SessionManagement: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'sessions' | 'activities' | 'analytics'>('overview');
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [activities, setActivities] = useState<SessionActivity[]>([]);
  const [stats, setStats] = useState<SessionStats>({
    totalActiveSessions: 0,
    uniqueUsers: 0,
    uniqueLocations: 0,
    uniqueDevices: 0,
    averageSessionDuration: 0,
    highRiskSessions: 0
  });
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedLocation, setSelectedLocation] = useState('');
  const [selectedSession, setSelectedSession] = useState<UserSession | null>(null);
  const [showSessionDetails, setShowSessionDetails] = useState(false);

  useEffect(() => {
    loadSessionData();
    const interval = setInterval(loadSessionData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadSessionData = async () => {
    try {
      setLoading(true);
      const [sessionsResponse, activitiesResponse] = await Promise.all([
        userService.getAllActiveSessions({
          page: 1,
          limit: 100,
          sortBy: 'lastActivity',
          sortOrder: 'desc'
        }),
        userService.getSessionActivities('', { page: 1, limit: 50 })
      ]);

      if (sessionsResponse.success) {
        setSessions(sessionsResponse.data);
        calculateStats(sessionsResponse.data);
      }

      if (activitiesResponse.success) {
        setActivities(activitiesResponse.data);
      }
    } catch (error) {
      console.error('Failed to load session data:', error);
    } finally {
      setLoading(false);
    }
  };

  const calculateStats = (sessionData: UserSession[]) => {
    const activeSessions = sessionData.filter(s => s.status === 'active');
    const uniqueUsers = new Set(activeSessions.map(s => s.userId)).size;
    const uniqueLocations = new Set(activeSessions.map(s => s.location).filter(Boolean)).size;
    const uniqueDevices = new Set(activeSessions.map(s => s.deviceFingerprint)).size;
    
    const totalDuration = activeSessions.reduce((acc, session) => {
      const duration = new Date(session.lastActivity).getTime() - new Date(session.createdAt).getTime();
      return acc + duration;
    }, 0);
    
    const averageSessionDuration = activeSessions.length > 0 ? totalDuration / activeSessions.length : 0;
    const highRiskSessions = activeSessions.filter(s => 
      s.location && s.location.includes('Unknown') || 
      new Date(s.lastActivity).getTime() - new Date(s.createdAt).getTime() > 24 * 60 * 60 * 1000
    ).length;

    setStats({
      totalActiveSessions: activeSessions.length,
      uniqueUsers,
      uniqueLocations,
      uniqueDevices,
      averageSessionDuration: Math.round(averageSessionDuration / (1000 * 60)), // Convert to minutes
      highRiskSessions
    });
  };

  const handleTerminateSession = async (sessionId: string, reason: string = 'Admin terminated') => {
    try {
      const response = await userService.terminateSession(sessionId, reason);
      if (response.success) {
        loadSessionData();
        setShowSessionDetails(false);
      }
    } catch (error) {
      console.error('Failed to terminate session:', error);
    }
  };

  const handleForceLogoutUser = async (userId: string, reason: string = 'Security policy violation') => {
    try {
      const response = await userService.forceLogoutUser(userId, reason);
      if (response.success) {
        loadSessionData();
      }
    } catch (error) {
      console.error('Failed to force logout user:', error);
    }
  };

  const getDeviceIcon = (userAgent: string) => {
    const ua = userAgent.toLowerCase();
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
      return <Smartphone className="w-4 h-4" />;
    } else if (ua.includes('tablet') || ua.includes('ipad')) {
      return <Tablet className="w-4 h-4" />;
    } else if (ua.includes('server') || ua.includes('bot')) {
      return <Server className="w-4 h-4" />;
    }
    return <Laptop className="w-4 h-4" />;
  };

  const getStatusColor = (status: UserSession['status']) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-100';
      case 'expired': return 'text-yellow-600 bg-yellow-100';
      case 'terminated': return 'text-red-600 bg-red-100';
      case 'forced_logout': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatDuration = (startTime: string, endTime: string) => {
    const duration = new Date(endTime).getTime() - new Date(startTime).getTime();
    const minutes = Math.floor(duration / (1000 * 60));
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }
    return `${minutes}m`;
  };

  const filteredSessions = sessions.filter(session => {
    const matchesSearch = searchTerm === '' || 
      session.userId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      session.ipAddress.includes(searchTerm) ||
      (session.location && session.location.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesUser = selectedUser === '' || session.userId === selectedUser;
    const matchesLocation = selectedLocation === '' || session.location === selectedLocation;
    
    return matchesSearch && matchesUser && matchesLocation;
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Session Management</h1>
          <p className="text-gray-600">Monitor and manage active user sessions</p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={loadSessionData}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Sessions</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalActiveSessions}</p>
            </div>
            <Monitor className="w-8 h-8 text-blue-600" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Users</p>
              <p className="text-2xl font-bold text-gray-900">{stats.uniqueUsers}</p>
            </div>
            <Users className="w-8 h-8 text-green-600" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Locations</p>
              <p className="text-2xl font-bold text-gray-900">{stats.uniqueLocations}</p>
            </div>
            <MapPin className="w-8 h-8 text-purple-600" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Devices</p>
              <p className="text-2xl font-bold text-gray-900">{stats.uniqueDevices}</p>
            </div>
            <Smartphone className="w-8 h-8 text-indigo-600" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Avg Duration</p>
              <p className="text-2xl font-bold text-gray-900">{stats.averageSessionDuration}m</p>
            </div>
            <Clock className="w-8 h-8 text-orange-600" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow border">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">High Risk</p>
              <p className="text-2xl font-bold text-red-600">{stats.highRiskSessions}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-600" />
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'overview', name: 'Overview', icon: Monitor },
            { id: 'sessions', name: 'Active Sessions', icon: Users },
            { id: 'activities', name: 'Recent Activities', icon: Clock },
            { id: 'analytics', name: 'Analytics', icon: Shield }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="w-4 h-4 mr-2" />
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'sessions' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="bg-white p-4 rounded-lg shadow border">
            <div className="flex flex-wrap gap-4">
              <div className="flex-1 min-w-64">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                  <input
                    type="text"
                    placeholder="Search sessions..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
              <select
                value={selectedUser}
                onChange={(e) => setSelectedUser(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">All Users</option>
                {Array.from(new Set(sessions.map(s => s.userId))).map(userId => (
                  <option key={userId} value={userId}>{userId}</option>
                ))}
              </select>
              <select
                value={selectedLocation}
                onChange={(e) => setSelectedLocation(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="">All Locations</option>
                {Array.from(new Set(sessions.map(s => s.location).filter(Boolean))).map(location => (
                  <option key={location} value={location}>{location}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Sessions Table */}
          <div className="bg-white rounded-lg shadow border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      User & Device
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Location & IP
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Session Info
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredSessions.map((session) => (
                    <tr key={session.sessionId} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {getDeviceIcon(session.userAgent)}
                          <div className="ml-3">
                            <div className="text-sm font-medium text-gray-900">{session.userId}</div>
                            <div className="text-sm text-gray-500 truncate max-w-48">
                              {session.userAgent.split(' ')[0]}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900 flex items-center">
                          <Globe className="w-4 h-4 mr-1 text-gray-400" />
                          {session.location || 'Unknown'}
                        </div>
                        <div className="text-sm text-gray-500">{session.ipAddress}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          Duration: {formatDuration(session.createdAt, session.lastActivity)}
                        </div>
                        <div className="text-sm text-gray-500">
                          Last activity: {new Date(session.lastActivity).toLocaleTimeString()}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(session.status)}`}>
                          {session.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-2">
                          <button
                            onClick={() => {
                              setSelectedSession(session);
                              setShowSessionDetails(true);
                            }}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          {session.status === 'active' && (
                            <button
                              onClick={() => handleTerminateSession(session.sessionId)}
                              className="text-red-600 hover:text-red-900"
                            >
                              <LogOut className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Session Details Modal */}
      {showSessionDetails && selectedSession && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Session Details</h3>
              <button
                onClick={() => setShowSessionDetails(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">User ID</label>
                  <p className="text-sm text-gray-900">{selectedSession.userId}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Session ID</label>
                  <p className="text-sm text-gray-900 font-mono">{selectedSession.sessionId}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">IP Address</label>
                  <p className="text-sm text-gray-900">{selectedSession.ipAddress}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Location</label>
                  <p className="text-sm text-gray-900">{selectedSession.location || 'Unknown'}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Created At</label>
                  <p className="text-sm text-gray-900">{new Date(selectedSession.createdAt).toLocaleString()}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Last Activity</label>
                  <p className="text-sm text-gray-900">{new Date(selectedSession.lastActivity).toLocaleString()}</p>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">User Agent</label>
                <p className="text-sm text-gray-900 break-all">{selectedSession.userAgent}</p>
              </div>
              
              {selectedSession.status === 'active' && (
                <div className="flex space-x-3 pt-4 border-t">
                  <button
                    onClick={() => handleTerminateSession(selectedSession.sessionId, 'Terminated by administrator')}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
                  >
                    Terminate Session
                  </button>
                  <button
                    onClick={() => handleForceLogoutUser(selectedSession.userId, 'Forced logout by administrator')}
                    className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
                  >
                    Force Logout User
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SessionManagement;
import React, { useState, useEffect } from 'react';
import { 
  Users, 
  UserPlus, 
  Shield, 
  Key, 
  Search, 
  Edit, 
  Trash2, 
  Eye, 
  CheckCircle,
  XCircle,
  AlertCircle,
  Clock,
  Lock,
  UserCheck,
  Activity
} from 'lucide-react';

interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  department: string;
  status: 'active' | 'inactive' | 'locked' | 'pending';
  lastLogin: string;
  createdAt: string;
  permissions: string[];
  mfaEnabled: boolean;
  phone?: string;
  location?: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
  isSystem: boolean;
  createdAt: string;
}

interface Permission {
  id: string;
  name: string;
  description: string;
  category: string;
  isSystem: boolean;
}

interface AuditLog {
  id: string;
  userId: string;
  username: string;
  action: string;
  resource: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  status: 'success' | 'failed';
}

const UserManagement: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'users' | 'roles' | 'permissions' | 'audit'>('users');
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterRole, setFilterRole] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading data
    setTimeout(() => {
      setUsers([
        {
          id: 'USR-001',
          username: 'admin',
          email: 'admin@company.com',
          firstName: 'System',
          lastName: 'Administrator',
          role: 'Super Admin',
          department: 'IT Security',
          status: 'active',
          lastLogin: '2024-01-15T14:30:00Z',
          createdAt: '2024-01-01T00:00:00Z',
          permissions: ['*'],
          mfaEnabled: true,
          phone: '+1-555-0101',
          location: 'New York, NY'
        },
        {
          id: 'USR-002',
          username: 'john.doe',
          email: 'john.doe@company.com',
          firstName: 'John',
          lastName: 'Doe',
          role: 'SOC Analyst',
          department: 'Security Operations',
          status: 'active',
          lastLogin: '2024-01-15T13:45:00Z',
          createdAt: '2024-01-05T00:00:00Z',
          permissions: ['alerts.read', 'incidents.read', 'threats.read'],
          mfaEnabled: true,
          phone: '+1-555-0102',
          location: 'Chicago, IL'
        },
        {
          id: 'USR-003',
          username: 'jane.smith',
          email: 'jane.smith@company.com',
          firstName: 'Jane',
          lastName: 'Smith',
          role: 'Security Manager',
          department: 'Security Operations',
          status: 'active',
          lastLogin: '2024-01-15T12:20:00Z',
          createdAt: '2024-01-03T00:00:00Z',
          permissions: ['alerts.*', 'incidents.*', 'users.read', 'reports.*'],
          mfaEnabled: true,
          phone: '+1-555-0103',
          location: 'San Francisco, CA'
        },
        {
          id: 'USR-004',
          username: 'bob.wilson',
          email: 'bob.wilson@company.com',
          firstName: 'Bob',
          lastName: 'Wilson',
          role: 'Compliance Officer',
          department: 'Risk & Compliance',
          status: 'inactive',
          lastLogin: '2024-01-10T16:30:00Z',
          createdAt: '2024-01-02T00:00:00Z',
          permissions: ['compliance.*', 'reports.read', 'audit.read'],
          mfaEnabled: false,
          phone: '+1-555-0104',
          location: 'Austin, TX'
        }
      ]);

      setRoles([
        {
          id: 'ROLE-001',
          name: 'Super Admin',
          description: 'Full system access with all permissions',
          permissions: ['*'],
          userCount: 1,
          isSystem: true,
          createdAt: '2024-01-01T00:00:00Z'
        },
        {
          id: 'ROLE-002',
          name: 'Security Manager',
          description: 'Manage security operations and team members',
          permissions: ['alerts.*', 'incidents.*', 'users.read', 'reports.*', 'threats.*'],
          userCount: 1,
          isSystem: false,
          createdAt: '2024-01-01T00:00:00Z'
        },
        {
          id: 'ROLE-003',
          name: 'SOC Analyst',
          description: 'Monitor and respond to security alerts',
          permissions: ['alerts.read', 'incidents.read', 'threats.read', 'investigations.create'],
          userCount: 1,
          isSystem: false,
          createdAt: '2024-01-01T00:00:00Z'
        },
        {
          id: 'ROLE-004',
          name: 'Compliance Officer',
          description: 'Monitor compliance and generate reports',
          permissions: ['compliance.*', 'reports.read', 'audit.read'],
          userCount: 1,
          isSystem: false,
          createdAt: '2024-01-01T00:00:00Z'
        }
      ]);

      setPermissions([
        { id: 'PERM-001', name: 'alerts.read', description: 'View security alerts', category: 'Alerts', isSystem: true },
        { id: 'PERM-002', name: 'alerts.write', description: 'Create and modify alerts', category: 'Alerts', isSystem: true },
        { id: 'PERM-003', name: 'incidents.read', description: 'View security incidents', category: 'Incidents', isSystem: true },
        { id: 'PERM-004', name: 'incidents.write', description: 'Create and modify incidents', category: 'Incidents', isSystem: true },
        { id: 'PERM-005', name: 'users.read', description: 'View user accounts', category: 'Users', isSystem: true },
        { id: 'PERM-006', name: 'users.write', description: 'Create and modify users', category: 'Users', isSystem: true },
        { id: 'PERM-007', name: 'reports.read', description: 'View reports', category: 'Reports', isSystem: true },
        { id: 'PERM-008', name: 'reports.write', description: 'Create and modify reports', category: 'Reports', isSystem: true },
        { id: 'PERM-009', name: 'compliance.read', description: 'View compliance data', category: 'Compliance', isSystem: true },
        { id: 'PERM-010', name: 'compliance.write', description: 'Manage compliance settings', category: 'Compliance', isSystem: true }
      ]);

      setAuditLogs([
        {
          id: 'LOG-001',
          userId: 'USR-001',
          username: 'admin',
          action: 'User Login',
          resource: 'Authentication System',
          timestamp: '2024-01-15T14:30:00Z',
          ipAddress: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          status: 'success'
        },
        {
          id: 'LOG-002',
          userId: 'USR-002',
          username: 'john.doe',
          action: 'View Alert',
          resource: 'Alert ALT-001',
          timestamp: '2024-01-15T14:25:00Z',
          ipAddress: '192.168.1.101',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          status: 'success'
        },
        {
          id: 'LOG-003',
          userId: 'USR-003',
          username: 'jane.smith',
          action: 'Create Incident',
          resource: 'Incident INC-001',
          timestamp: '2024-01-15T14:20:00Z',
          ipAddress: '192.168.1.102',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
          status: 'success'
        }
      ]);

      setIsLoading(false);
    }, 1000);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-50';
      case 'inactive': return 'text-gray-600 bg-gray-50';
      case 'locked': return 'text-red-600 bg-red-50';
      case 'pending': return 'text-yellow-600 bg-yellow-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'inactive': return <XCircle className="w-4 h-4 text-gray-500" />;
      case 'locked': return <Lock className="w-4 h-4 text-red-500" />;
      case 'pending': return <Clock className="w-4 h-4 text-yellow-500" />;
      default: return <AlertCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         `${user.firstName} ${user.lastName}`.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = filterStatus === 'all' || user.status === filterStatus;
    const matchesRole = filterRole === 'all' || user.role === filterRole;
    return matchesSearch && matchesStatus && matchesRole;
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
          <h1 className="text-3xl font-bold text-gray-900 mb-2">User Management & RBAC</h1>
          <p className="text-gray-600">Manage users, roles, and permissions for your security platform</p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Users</p>
                <p className="text-2xl font-bold text-blue-600">{users.length}</p>
              </div>
              <Users className="h-8 w-8 text-blue-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Users</p>
                <p className="text-2xl font-bold text-green-600">{users.filter(u => u.status === 'active').length}</p>
              </div>
              <UserCheck className="h-8 w-8 text-green-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Roles</p>
                <p className="text-2xl font-bold text-purple-600">{roles.length}</p>
              </div>
              <Shield className="h-8 w-8 text-purple-600" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">MFA Enabled</p>
                <p className="text-2xl font-bold text-orange-600">{users.filter(u => u.mfaEnabled).length}</p>
              </div>
              <Key className="h-8 w-8 text-orange-600" />
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              {[
                { id: 'users', name: 'Users', icon: Users },
                { id: 'roles', name: 'Roles', icon: Shield },
                { id: 'permissions', name: 'Permissions', icon: Key },
                { id: 'audit', name: 'Audit Log', icon: Activity }
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
            {activeTab === 'users' && (
              <div>
                {/* User Management Header */}
                <div className="flex justify-between items-center mb-6">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2">
                      <Search className="w-4 h-4 text-gray-400" />
                      <input
                        type="text"
                        placeholder="Search users..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                      />
                    </div>
                    <select
                      value={filterStatus}
                      onChange={(e) => setFilterStatus(e.target.value)}
                      className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                    >
                      <option value="all">All Status</option>
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                      <option value="locked">Locked</option>
                      <option value="pending">Pending</option>
                    </select>
                    <select
                      value={filterRole}
                      onChange={(e) => setFilterRole(e.target.value)}
                      className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                    >
                      <option value="all">All Roles</option>
                      {roles.map(role => (
                        <option key={role.id} value={role.name}>{role.name}</option>
                      ))}
                    </select>
                  </div>
                  <button 
                    className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                  >
                    <UserPlus className="w-4 h-4" />
                    <span>Add User</span>
                  </button>
                </div>

                {/* Users Table */}
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">MFA</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {filteredUsers.map((user) => (
                        <tr key={user.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <div className="flex-shrink-0 h-10 w-10">
                                <div className="h-10 w-10 rounded-full bg-blue-500 flex items-center justify-center">
                                  <span className="text-white font-medium">
                                    {user.firstName[0]}{user.lastName[0]}
                                  </span>
                                </div>
                              </div>
                              <div className="ml-4">
                                <div className="text-sm font-medium text-gray-900">
                                  {user.firstName} {user.lastName}
                                </div>
                                <div className="text-sm text-gray-500">{user.email}</div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.role}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.department}</td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                              {getStatusIcon(user.status)}
                              <span className="ml-1">{user.status}</span>
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(user.lastLogin).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {user.mfaEnabled ? (
                              <CheckCircle className="w-5 h-5 text-green-500" />
                            ) : (
                              <XCircle className="w-5 h-5 text-red-500" />
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <div className="flex items-center space-x-2">
                              <button 
                                className="text-blue-600 hover:text-blue-900"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button className="text-gray-600 hover:text-gray-900">
                                <Edit className="w-4 h-4" />
                              </button>
                              <button className="text-red-600 hover:text-red-900">
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'roles' && (
              <div>
                <div className="flex justify-between items-center mb-6">
                  <h3 className="text-lg font-semibold text-gray-900">Role Management</h3>
                  <button 
                    className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                  >
                    <Shield className="w-4 h-4" />
                    <span>Create Role</span>
                  </button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {roles.map((role) => (
                    <div key={role.id} className="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                      <div className="flex items-start justify-between mb-4">
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900">{role.name}</h3>
                          <p className="text-sm text-gray-600">{role.description}</p>
                        </div>
                        {role.isSystem && (
                          <span className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded">System</span>
                        )}
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-600">Users:</span>
                          <span className="font-medium">{role.userCount}</span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-600">Permissions:</span>
                          <span className="font-medium">{role.permissions.length}</span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-gray-600">Created:</span>
                          <span className="font-medium">{new Date(role.createdAt).toLocaleDateString()}</span>
                        </div>
                      </div>
                      <div className="mt-4 flex items-center space-x-2">
                        <button 
                          className="flex-1 px-3 py-2 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
                        >
                          View Details
                        </button>
                        {!role.isSystem && (
                          <button className="px-3 py-2 text-sm bg-gray-50 text-gray-600 rounded hover:bg-gray-100">
                            Edit
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'permissions' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-6">System Permissions</h3>
                <div className="space-y-6">
                  {['Alerts', 'Incidents', 'Users', 'Reports', 'Compliance'].map((category) => (
                    <div key={category} className="border border-gray-200 rounded-lg p-6">
                      <h4 className="text-md font-semibold text-gray-900 mb-4">{category}</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {permissions
                          .filter(perm => perm.category === category)
                          .map((permission) => (
                            <div key={permission.id} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                              <div>
                                <p className="font-medium text-gray-900">{permission.name}</p>
                                <p className="text-sm text-gray-600">{permission.description}</p>
                              </div>
                              {permission.isSystem && (
                                <span className="px-2 py-1 bg-blue-100 text-blue-600 text-xs rounded">System</span>
                              )}
                            </div>
                          ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'audit' && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-6">Audit Log</h3>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resource</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                            {log.username}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{log.action}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{log.resource}</td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.ipAddress}</td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              log.status === 'success' ? 'text-green-600 bg-green-50' : 'text-red-600 bg-red-50'
                            }`}>
                              {log.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserManagement;
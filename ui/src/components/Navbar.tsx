import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  FileText, 
  Microscope, 
  Brain, 
  Server, 
  Users, 
  Database, 
  BarChart3, 
  LogOut,
  Home,
  Target,
  Eye,
  Bell
} from 'lucide-react'

interface NavbarProps {
  onLogout: () => void
}

const Navbar: React.FC<NavbarProps> = ({ onLogout }) => {
  const location = useLocation()

  const navItems = [
    { path: '/dashboard', icon: Home, label: 'SOC Dashboard' },
    { path: '/threat-hunting', icon: Target, label: 'Threat Hunting' },
    { path: '/incident-response', icon: AlertTriangle, label: 'Incident Response' },
    { path: '/threat-intel', icon: Brain, label: 'Threat Intelligence' },
    { path: '/ueba', icon: Eye, label: 'User Analytics' },
    { path: '/assets', icon: Server, label: 'Asset Inventory' },
    { path: '/alerts', icon: Bell, label: 'Alert Center' },
    { path: '/users', icon: Users, label: 'User Management' },
    { path: '/compliance', icon: FileText, label: 'Compliance' },
    { path: '/forensics', icon: Microscope, label: 'Forensics Lab' },
    { path: '/query', icon: Database, label: 'Query Workbench' },
    { path: '/advanced', icon: BarChart3, label: 'Analytics' },
    { path: '/agents', icon: Activity, label: 'Agent Management' },
  ]

  return (
    <nav className="w-64 bg-slate-900 text-white flex flex-col">
      <div className="p-4 border-b border-slate-700">
        <div className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Musafir SecOps</h1>
            <p className="text-xs text-slate-400">EDR • XDR • SIEM</p>
          </div>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto py-4">
        <div className="px-3 mb-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Security Operations
          </h2>
          {navItems.slice(0, 4).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-lg mb-1 transition-colors ${
                location.pathname === item.path
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <item.icon className="h-5 w-5" />
              <span className="text-sm">{item.label}</span>
            </Link>
          ))}
        </div>

        <div className="px-3 mb-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Risk Management
          </h2>
          {navItems.slice(4, 7).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-lg mb-1 transition-colors ${
                location.pathname === item.path
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <item.icon className="h-5 w-5" />
              <span className="text-sm">{item.label}</span>
            </Link>
          ))}
        </div>

        <div className="px-3 mb-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Investigation & Analysis
          </h2>
          {navItems.slice(7, 10).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-lg mb-1 transition-colors ${
                location.pathname === item.path
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <item.icon className="h-5 w-5" />
              <span className="text-sm">{item.label}</span>
            </Link>
          ))}
        </div>

        <div className="px-3">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Administration
          </h2>
          {navItems.slice(10).map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center space-x-3 px-3 py-2 rounded-lg mb-1 transition-colors ${
                location.pathname === item.path
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <item.icon className="h-5 w-5" />
              <span className="text-sm">{item.label}</span>
            </Link>
          ))}
        </div>
      </div>
      
      <div className="p-4 border-t border-slate-700">
        <button
          onClick={onLogout}
          className="flex items-center space-x-3 px-3 py-2 rounded-lg w-full text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
        >
          <LogOut className="h-5 w-5" />
          <span className="text-sm">Logout</span>
        </button>
      </div>
    </nav>
  )
}

export default Navbar
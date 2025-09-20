# MUSAFIR Central Web UI - Frontend Specifications

## 📋 Table of Contents
1. [Technology Stack & Architecture](#technology-stack--architecture)
2. [Dashboard Components](#dashboard-components)
3. [EDR (Endpoint Detection & Response)](#edr-endpoint-detection--response)
4. [XDR (Extended Detection & Response)](#xdr-extended-detection--response)
5. [SIEM (Security Information & Event Management)](#siem-security-information--event-management)
6. [Component Library](#component-library)
7. [State Management](#state-management)
8. [Real-time Updates](#real-time-updates)
9. [Responsive Design](#responsive-design)

---

## 🛠️ Technology Stack & Architecture

### Frontend Framework
```json
{
  "framework": "React 18.2+",
  "language": "TypeScript 5.0+",
  "build_tool": "Vite 4.0+",
  "styling": "Tailwind CSS 3.3+",
  "ui_library": "Headless UI + Custom Components",
  "charts": "Chart.js 4.0+ / D3.js 7.0+",
  "maps": "Leaflet 1.9+",
  "icons": "Heroicons 2.0+",
  "animations": "Framer Motion 10.0+"
}
```

### Project Structure
```
frontend/
├── public/
│   ├── favicon.ico
│   └── manifest.json
├── src/
│   ├── components/           # Reusable UI components
│   │   ├── common/          # Generic components
│   │   ├── charts/          # Chart components
│   │   ├── forms/           # Form components
│   │   └── layout/          # Layout components
│   ├── pages/               # Page components
│   │   ├── dashboard/       # Main dashboard
│   │   ├── edr/            # EDR specific pages
│   │   ├── xdr/            # XDR specific pages
│   │   ├── siem/           # SIEM specific pages
│   │   ├── agents/         # Agent management
│   │   ├── alerts/         # Alert management
│   │   ├── investigations/ # Investigation workflows
│   │   └── settings/       # Configuration pages
│   ├── hooks/              # Custom React hooks
│   ├── services/           # API services
│   ├── store/              # State management
│   ├── types/              # TypeScript definitions
│   ├── utils/              # Utility functions
│   └── styles/             # Global styles
├── package.json
├── tailwind.config.js
├── vite.config.ts
└── tsconfig.json
```

### Package.json Dependencies
```json
{
  "name": "musafir-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "test": "vitest"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "@reduxjs/toolkit": "^1.9.0",
    "react-redux": "^8.0.0",
    "@headlessui/react": "^1.7.0",
    "@heroicons/react": "^2.0.0",
    "chart.js": "^4.2.0",
    "react-chartjs-2": "^5.2.0",
    "d3": "^7.8.0",
    "leaflet": "^1.9.0",
    "react-leaflet": "^4.2.0",
    "framer-motion": "^10.0.0",
    "date-fns": "^2.29.0",
    "react-hook-form": "^7.43.0",
    "zod": "^3.20.0",
    "@hookform/resolvers": "^2.9.0",
    "socket.io-client": "^4.6.0",
    "axios": "^1.3.0",
    "react-query": "^3.39.0",
    "react-table": "^7.8.0",
    "react-virtual": "^2.10.0"
  },
  "devDependencies": {
    "@types/react": "^18.0.0",
    "@types/react-dom": "^18.0.0",
    "@types/d3": "^7.4.0",
    "@types/leaflet": "^1.9.0",
    "@vitejs/plugin-react": "^3.1.0",
    "typescript": "^4.9.0",
    "vite": "^4.1.0",
    "tailwindcss": "^3.2.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "eslint": "^8.35.0",
    "@typescript-eslint/eslint-plugin": "^5.54.0",
    "@typescript-eslint/parser": "^5.54.0",
    "vitest": "^0.28.0"
  }
}
```

---

## 📊 Dashboard Components

### Main Dashboard Layout
```tsx
// File: src/pages/dashboard/MainDashboard.tsx
import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { motion } from 'framer-motion';

import { ThreatOverview } from '../components/dashboard/ThreatOverview';
import { AgentStatus } from '../components/dashboard/AgentStatus';
import { RealtimeEvents } from '../components/dashboard/RealtimeEvents';
import { ThreatMap } from '../components/dashboard/ThreatMap';
import { AlertsSummary } from '../components/dashboard/AlertsSummary';
import { SystemHealth } from '../components/dashboard/SystemHealth';

interface DashboardData {
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
  activeAlerts: number;
  connectedAgents: number;
  eventsPerSecond: number;
  threatScore: number;
  statistics: {
    events24h: number;
    threatsDetected24h: number;
    incidentsResolved24h: number;
    meanTimeToDetection: number;
    meanTimeToResponse: number;
  };
}

export const MainDashboard: React.FC = () => {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [timeRange, setTimeRange] = useState('24h');
  const dispatch = useDispatch();

  useEffect(() => {
    // Fetch dashboard data
    fetchDashboardData();
    
    // Set up real-time updates
    const interval = setInterval(fetchDashboardData, 30000); // 30 seconds
    
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchDashboardData = async () => {
    try {
      const response = await fetch('/api/v1/dashboard/overview');
      const data = await response.json();
      setDashboardData(data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    }
  };

  if (!dashboardData) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                MUSAFIR Security Operations Center
              </h1>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Real-time threat monitoring and incident response
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
              <ThreatLevelIndicator level={dashboardData.threatLevel} />
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="px-6 py-6">
        {/* Key Metrics Row */}
        <motion.div 
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <MetricCard
            title="Active Alerts"
            value={dashboardData.activeAlerts}
            trend="+12%"
            trendDirection="up"
            color="red"
            icon="ExclamationTriangleIcon"
          />
          <MetricCard
            title="Connected Agents"
            value={dashboardData.connectedAgents}
            trend="+2"
            trendDirection="up"
            color="green"
            icon="ComputerDesktopIcon"
          />
          <MetricCard
            title="Events/Second"
            value={dashboardData.eventsPerSecond}
            trend="stable"
            trendDirection="stable"
            color="blue"
            icon="ChartBarIcon"
          />
          <MetricCard
            title="Threat Score"
            value={dashboardData.threatScore}
            trend="-5%"
            trendDirection="down"
            color="orange"
            icon="ShieldExclamationIcon"
          />
          <MetricCard
            title="MTTR"
            value={`${Math.round(dashboardData.statistics.meanTimeToResponse / 60)}m`}
            trend="-15%"
            trendDirection="down"
            color="purple"
            icon="ClockIcon"
          />
        </motion.div>

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Threat Overview */}
          <motion.div 
            className="lg:col-span-2"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <ThreatOverview timeRange={timeRange} />
          </motion.div>

          {/* Agent Status */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <AgentStatus />
          </motion.div>
        </div>

        {/* Secondary Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Threat Map */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            <ThreatMap />
          </motion.div>

          {/* Real-time Events */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <RealtimeEvents />
          </motion.div>
        </div>

        {/* Bottom Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Alerts Summary */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.5 }}
          >
            <AlertsSummary />
          </motion.div>

          {/* System Health */}
          <motion.div 
            className="lg:col-span-2"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.6 }}
          >
            <SystemHealth />
          </motion.div>
        </div>
      </main>
    </div>
  );
};

// Metric Card Component
interface MetricCardProps {
  title: string;
  value: number | string;
  trend: string;
  trendDirection: 'up' | 'down' | 'stable';
  color: 'red' | 'green' | 'blue' | 'orange' | 'purple';
  icon: string;
}

const MetricCard: React.FC<MetricCardProps> = ({ 
  title, value, trend, trendDirection, color, icon 
}) => {
  const colorClasses = {
    red: 'bg-red-50 text-red-700 border-red-200',
    green: 'bg-green-50 text-green-700 border-green-200',
    blue: 'bg-blue-50 text-blue-700 border-blue-200',
    orange: 'bg-orange-50 text-orange-700 border-orange-200',
    purple: 'bg-purple-50 text-purple-700 border-purple-200',
  };

  const trendColors = {
    up: 'text-red-600',
    down: 'text-green-600',
    stable: 'text-gray-600',
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          {/* Icon component would go here */}
        </div>
      </div>
      <div className="mt-4 flex items-center">
        <span className={`text-sm font-medium ${trendColors[trendDirection]}`}>
          {trend}
        </span>
        <span className="text-sm text-gray-600 dark:text-gray-400 ml-2">vs last period</span>
      </div>
    </div>
  );
};
```

### Threat Overview Component
```tsx
// File: src/components/dashboard/ThreatOverview.tsx
import React, { useState, useEffect } from 'react';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

interface ThreatData {
  timeline: Array<{
    timestamp: string;
    threatCount: number;
    severityBreakdown: {
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
  }>;
  topThreats: Array<{
    threatType: string;
    count: number;
    trend: 'up' | 'down' | 'stable';
  }>;
  attackVectors: Array<{
    vector: string;
    count: number;
    percentage: number;
  }>;
}

interface ThreatOverviewProps {
  timeRange: string;
}

export const ThreatOverview: React.FC<ThreatOverviewProps> = ({ timeRange }) => {
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  const [activeTab, setActiveTab] = useState<'timeline' | 'vectors' | 'types'>('timeline');

  useEffect(() => {
    fetchThreatData();
  }, [timeRange]);

  const fetchThreatData = async () => {
    try {
      const response = await fetch(`/api/v1/dashboard/threats?time_range=${timeRange}`);
      const data = await response.json();
      setThreatData(data);
    } catch (error) {
      console.error('Failed to fetch threat data:', error);
    }
  };

  if (!threatData) {
    return <div className="animate-pulse bg-gray-200 h-96 rounded-lg"></div>;
  }

  const timelineChartData = {
    labels: threatData.timeline.map(item => 
      new Date(item.timestamp).toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit' 
      })
    ),
    datasets: [
      {
        label: 'Critical',
        data: threatData.timeline.map(item => item.severityBreakdown.critical),
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        tension: 0.4,
      },
      {
        label: 'High',
        data: threatData.timeline.map(item => item.severityBreakdown.high),
        borderColor: 'rgb(245, 158, 11)',
        backgroundColor: 'rgba(245, 158, 11, 0.1)',
        tension: 0.4,
      },
      {
        label: 'Medium',
        data: threatData.timeline.map(item => item.severityBreakdown.medium),
        borderColor: 'rgb(59, 130, 246)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        tension: 0.4,
      },
      {
        label: 'Low',
        data: threatData.timeline.map(item => item.severityBreakdown.low),
        borderColor: 'rgb(34, 197, 94)',
        backgroundColor: 'rgba(34, 197, 94, 0.1)',
        tension: 0.4,
      },
    ],
  };

  const attackVectorChartData = {
    labels: threatData.attackVectors.map(item => item.vector),
    datasets: [
      {
        data: threatData.attackVectors.map(item => item.count),
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(245, 158, 11, 0.8)',
          'rgba(59, 130, 246, 0.8)',
          'rgba(34, 197, 94, 0.8)',
          'rgba(168, 85, 247, 0.8)',
        ],
        borderColor: [
          'rgb(239, 68, 68)',
          'rgb(245, 158, 11)',
          'rgb(59, 130, 246)',
          'rgb(34, 197, 94)',
          'rgb(168, 85, 247)',
        ],
        borderWidth: 2,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Threat Overview
          </h3>
          <div className="flex space-x-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1">
            {[
              { key: 'timeline', label: 'Timeline' },
              { key: 'vectors', label: 'Attack Vectors' },
              { key: 'types', label: 'Threat Types' },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as any)}
                className={`px-3 py-1 text-sm font-medium rounded-md transition-colors ${
                  activeTab === tab.key
                    ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow-sm'
                    : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="p-6">
        {activeTab === 'timeline' && (
          <div className="h-80">
            <Line data={timelineChartData} options={chartOptions} />
          </div>
        )}

        {activeTab === 'vectors' && (
          <div className="h-80">
            <Doughnut data={attackVectorChartData} options={chartOptions} />
          </div>
        )}

        {activeTab === 'types' && (
          <div className="space-y-4">
            {threatData.topThreats.map((threat, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {threat.threatType}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {threat.count} incidents
                  </span>
                  <div className={`flex items-center ${
                    threat.trend === 'up' ? 'text-red-600' : 
                    threat.trend === 'down' ? 'text-green-600' : 'text-gray-600'
                  }`}>
                    {/* Trend icon would go here */}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
```

---

## 🛡️ EDR (Endpoint Detection & Response)

### EDR Dashboard
```tsx
// File: src/pages/edr/EDRDashboard.tsx
import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

import { EndpointList } from '../../components/edr/EndpointList';
import { ProcessMonitor } from '../../components/edr/ProcessMonitor';
import { FileIntegrityMonitor } from '../../components/edr/FileIntegrityMonitor';
import { ThreatHunting } from '../../components/edr/ThreatHunting';
import { ForensicsCollector } from '../../components/edr/ForensicsCollector';

export const EDRDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState('endpoints');
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);

  const tabs = [
    { id: 'endpoints', label: 'Endpoints', icon: 'ComputerDesktopIcon' },
    { id: 'processes', label: 'Process Monitor', icon: 'CpuChipIcon' },
    { id: 'files', label: 'File Integrity', icon: 'DocumentIcon' },
    { id: 'hunting', label: 'Threat Hunting', icon: 'MagnifyingGlassIcon' },
    { id: 'forensics', label: 'Forensics', icon: 'FingerPrintIcon' },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-4">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Endpoint Detection & Response
          </h1>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Monitor and respond to endpoint threats in real-time
          </p>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar Navigation */}
        <nav className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 min-h-screen">
          <div className="p-4">
            <div className="space-y-2">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                    activeTab === tab.id
                      ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                  }`}
                >
                  {/* Icon would go here */}
                  <span className="font-medium">{tab.label}</span>
                </button>
              ))}
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            {activeTab === 'endpoints' && (
              <EndpointList 
                onSelectEndpoint={setSelectedEndpoint}
                selectedEndpoint={selectedEndpoint}
              />
            )}
            {activeTab === 'processes' && (
              <ProcessMonitor endpointId={selectedEndpoint} />
            )}
            {activeTab === 'files' && (
              <FileIntegrityMonitor endpointId={selectedEndpoint} />
            )}
            {activeTab === 'hunting' && (
              <ThreatHunting />
            )}
            {activeTab === 'forensics' && (
              <ForensicsCollector endpointId={selectedEndpoint} />
            )}
          </motion.div>
        </main>
      </div>
    </div>
  );
};
```

### Endpoint List Component
```tsx
// File: src/components/edr/EndpointList.tsx
import React, { useState, useEffect } from 'react';
import { useTable, useSortBy, useFilters, usePagination } from 'react-table';

interface Endpoint {
  id: string;
  agentId: string;
  hostname: string;
  ipAddress: string;
  osInfo: {
    name: string;
    version: string;
    architecture: string;
  };
  status: 'online' | 'offline' | 'error';
  lastHeartbeat: string;
  threatScore: number;
  events24h: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

interface EndpointListProps {
  onSelectEndpoint: (endpointId: string) => void;
  selectedEndpoint: string | null;
}

export const EndpointList: React.FC<EndpointListProps> = ({ 
  onSelectEndpoint, 
  selectedEndpoint 
}) => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetchEndpoints();
  }, []);

  const fetchEndpoints = async () => {
    try {
      const response = await fetch('/api/v1/agents');
      const data = await response.json();
      setEndpoints(data.agents);
    } catch (error) {
      console.error('Failed to fetch endpoints:', error);
    } finally {
      setLoading(false);
    }
  };

  const columns = React.useMemo(
    () => [
      {
        Header: 'Hostname',
        accessor: 'hostname',
        Cell: ({ row }: any) => (
          <div className="flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${
              row.original.status === 'online' ? 'bg-green-500' :
              row.original.status === 'offline' ? 'bg-gray-400' : 'bg-red-500'
            }`}></div>
            <div>
              <div className="font-medium text-gray-900 dark:text-white">
                {row.original.hostname}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                {row.original.ipAddress}
              </div>
            </div>
          </div>
        ),
      },
      {
        Header: 'OS',
        accessor: 'osInfo.name',
        Cell: ({ row }: any) => (
          <div>
            <div className="text-sm font-medium text-gray-900 dark:text-white">
              {row.original.osInfo.name}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {row.original.osInfo.version}
            </div>
          </div>
        ),
      },
      {
        Header: 'Status',
        accessor: 'status',
        Cell: ({ value }: any) => (
          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
            value === 'online' ? 'bg-green-100 text-green-800' :
            value === 'offline' ? 'bg-gray-100 text-gray-800' :
            'bg-red-100 text-red-800'
          }`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </span>
        ),
      },
      {
        Header: 'Threat Score',
        accessor: 'threatScore',
        Cell: ({ value }: any) => (
          <div className="flex items-center space-x-2">
            <div className="flex-1 bg-gray-200 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${
                  value < 30 ? 'bg-green-500' :
                  value < 60 ? 'bg-yellow-500' :
                  value < 80 ? 'bg-orange-500' : 'bg-red-500'
                }`}
                style={{ width: `${value}%` }}
              ></div>
            </div>
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              {value}
            </span>
          </div>
        ),
      },
      {
        Header: 'Events (24h)',
        accessor: 'events24h',
        Cell: ({ value }: any) => (
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {value.toLocaleString()}
          </span>
        ),
      },
      {
        Header: 'Risk Level',
        accessor: 'riskLevel',
        Cell: ({ value }: any) => (
          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
            value === 'low' ? 'bg-green-100 text-green-800' :
            value === 'medium' ? 'bg-yellow-100 text-yellow-800' :
            value === 'high' ? 'bg-orange-100 text-orange-800' :
            'bg-red-100 text-red-800'
          }`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </span>
        ),
      },
      {
        Header: 'Actions',
        Cell: ({ row }: any) => (
          <div className="flex space-x-2">
            <button
              onClick={() => onSelectEndpoint(row.original.id)}
              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              View Details
            </button>
            <button className="text-gray-600 hover:text-gray-800 text-sm font-medium">
              Isolate
            </button>
          </div>
        ),
      },
    ],
    [onSelectEndpoint]
  );

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    page,
    prepareRow,
    canPreviousPage,
    canNextPage,
    pageOptions,
    pageCount,
    gotoPage,
    nextPage,
    previousPage,
    setPageSize,
    state: { pageIndex, pageSize },
  } = useTable(
    {
      columns,
      data: endpoints,
      initialState: { pageIndex: 0, pageSize: 10 },
    },
    useFilters,
    useSortBy,
    usePagination
  );

  if (loading) {
    return <div className="animate-pulse">Loading endpoints...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Endpoints ({endpoints.length})
          </h2>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Monitor and manage all connected endpoints
          </p>
        </div>
        <div className="flex space-x-3">
          <input
            type="text"
            placeholder="Search endpoints..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table {...getTableProps()} className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            {headerGroups.map(headerGroup => (
              <tr {...headerGroup.getHeaderGroupProps()}>
                {headerGroup.headers.map(column => (
                  <th
                    {...column.getHeaderProps(column.getSortByToggleProps())}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                  >
                    <div className="flex items-center space-x-1">
                      <span>{column.render('Header')}</span>
                      {column.isSorted ? (
                        column.isSortedDesc ? (
                          <span>↓</span>
                        ) : (
                          <span>↑</span>
                        )
                      ) : (
                        <span className="text-gray-400">↕</span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody {...getTableBodyProps()} className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {page.map(row => {
              prepareRow(row);
              return (
                <tr
                  {...row.getRowProps()}
                  className={`hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer ${
                    selectedEndpoint === row.original.id ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                  onClick={() => onSelectEndpoint(row.original.id)}
                >
                  {row.cells.map(cell => (
                    <td {...cell.getCellProps()} className="px-6 py-4 whitespace-nowrap">
                      {cell.render('Cell')}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="bg-white dark:bg-gray-800 px-4 py-3 border-t border-gray-200 dark:border-gray-700 sm:px-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Showing {pageIndex * currentPageSize + 1} to {Math.min((pageIndex + 1) * currentPageSize, data.length)} of {data.length} results
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => previousPage()}
              disabled={!canPreviousPage}
              className="px-3 py-1 text-sm border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Previous
            </button>
            <button
              onClick={() => nextPage()}
              disabled={!canNextPage}
              className="px-3 py-1 text-sm border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
```

// File: src/components/common/AlertBadge.tsx
interface AlertBadgeProps {
  severity: 'low' | 'medium' | 'high' | 'critical';
  count?: number;
  size?: 'sm' | 'md' | 'lg';
}

export const AlertBadge: React.FC<AlertBadgeProps> = ({ 
  severity, 
  count, 
  size = 'md' 
}) => {
  const severityStyles = {
    low: 'bg-green-100 text-green-800 border-green-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    critical: 'bg-red-100 text-red-800 border-red-200',
  };

  const sizeStyles = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-3 py-1 text-sm',
    lg: 'px-4 py-2 text-base',
  };

  return (
    <span className={`inline-flex items-center font-semibold rounded-full border ${severityStyles[severity]} ${sizeStyles[size]}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
      {count !== undefined && (
        <span className="ml-1 bg-white rounded-full px-2 py-0.5 text-xs">
          {count}
        </span>
      )}
    </span>
  );
};

// File: src/components/common/StatusIndicator.tsx
interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'error' | 'warning';
  label?: string;
  showLabel?: boolean;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({ 
  status, 
  label, 
  showLabel = true 
}) => {
  const statusStyles = {
    online: 'bg-green-500',
    offline: 'bg-gray-400',
    error: 'bg-red-500',
    warning: 'bg-yellow-500',
  };

  const statusLabels = {
    online: 'Online',
    offline: 'Offline',
    error: 'Error',
    warning: 'Warning',
  };

  return (
    <div className="flex items-center space-x-2">
      <div className={`w-3 h-3 rounded-full ${statusStyles[status]}`}></div>
      {showLabel && (
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          {label || statusLabels[status]}
        </span>
      )}
    </div>
  );
};

---

## 🔄 State Management

### Redux Store Configuration
```tsx
// File: src/store/index.ts
import { configureStore } from '@reduxjs/toolkit';
import { authSlice } from './slices/authSlice';
import { dashboardSlice } from './slices/dashboardSlice';
import { agentsSlice } from './slices/agentsSlice';
import { alertsSlice } from './slices/alertsSlice';
import { threatsSlice } from './slices/threatsSlice';

export const store = configureStore({
  reducer: {
    auth: authSlice.reducer,
    dashboard: dashboardSlice.reducer,
    agents: agentsSlice.reducer,
    alerts: alertsSlice.reducer,
    threats: threatsSlice.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST'],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
```

### Dashboard Slice
```tsx
// File: src/store/slices/dashboardSlice.ts
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';

interface DashboardState {
  overview: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    activeAlerts: number;
    connectedAgents: number;
    eventsPerSecond: number;
    threatScore: number;
  } | null;
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;
}

const initialState: DashboardState = {
  overview: null,
  loading: false,
  error: null,
  lastUpdated: null,
};

export const fetchDashboardOverview = createAsyncThunk(
  'dashboard/fetchOverview',
  async (timeRange: string) => {
    const response = await fetch(`/api/v1/dashboard/overview?time_range=${timeRange}`);
    if (!response.ok) {
      throw new Error('Failed to fetch dashboard overview');
    }
    return response.json();
  }
);

export const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    updateRealTimeMetrics: (state, action: PayloadAction<Partial<DashboardState['overview']>>) => {
      if (state.overview) {
        state.overview = { ...state.overview, ...action.payload };
      }
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchDashboardOverview.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchDashboardOverview.fulfilled, (state, action) => {
        state.loading = false;
        state.overview = action.payload;
        state.lastUpdated = new Date().toISOString();
      })
      .addCase(fetchDashboardOverview.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch dashboard data';
      });
  },
});

export const { updateRealTimeMetrics, clearError } = dashboardSlice.actions;
```

---

## 📡 Real-time Updates

### WebSocket Service
```tsx
// File: src/services/websocket.ts
import { io, Socket } from 'socket.io-client';
import { store } from '../store';
import { updateRealTimeMetrics } from '../store/slices/dashboardSlice';

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  connect() {
    this.socket = io(process.env.REACT_APP_WS_URL || 'ws://localhost:8080', {
      transports: ['websocket'],
      upgrade: true,
    });

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
    });

    this.socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      this.handleReconnect();
    });

    // Dashboard updates
    this.socket.on('dashboard:metrics', (data) => {
      store.dispatch(updateRealTimeMetrics(data));
    });

    // Alert updates
    this.socket.on('alert:new', (alert) => {
      // Handle new alert
      console.log('New alert received:', alert);
    });

    // Agent status updates
    this.socket.on('agent:status', (agentUpdate) => {
      // Handle agent status change
      console.log('Agent status update:', agentUpdate);
    });

    // Threat detection updates
    this.socket.on('threat:detected', (threat) => {
      // Handle new threat detection
      console.log('New threat detected:', threat);
    });
  }

  private handleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => {
        console.log(`Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        this.connect();
      }, 1000 * this.reconnectAttempts);
    }
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  emit(event: string, data: any) {
    if (this.socket) {
      this.socket.emit(event, data);
    }
  }
}

export const websocketService = new WebSocketService();
```

---

## 📱 Responsive Design

### Tailwind Configuration
```js
// File: tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a',
        },
        danger: {
          50: '#fef2f2',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          900: '#7f1d1d',
        },
        success: {
          50: '#f0fdf4',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          900: '#14532d',
        },
        warning: {
          50: '#fffbeb',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          900: '#78350f',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
      },
      screens: {
        'xs': '475px',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
}
```

### Mobile-First Components
```tsx
// File: src/components/layout/MobileNavigation.tsx
import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface MobileNavigationProps {
  isOpen: boolean;
  onClose: () => void;
  navigationItems: Array<{
    id: string;
    label: string;
    icon: string;
    href: string;
  }>;
}

export const MobileNavigation: React.FC<MobileNavigationProps> = ({
  isOpen,
  onClose,
  navigationItems,
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
            onClick={onClose}
          />

          {/* Mobile Menu */}
          <motion.div
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'tween', duration: 0.3 }}
            className="fixed inset-y-0 left-0 w-64 bg-white dark:bg-gray-800 shadow-xl z-50 lg:hidden"
          >
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                MUSAFIR
              </h2>
              <button
                onClick={onClose}
                className="p-2 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <span className="sr-only">Close menu</span>
                {/* Close icon */}
              </button>
            </div>

            <nav className="mt-4 px-4">
              <div className="space-y-2">
                {navigationItems.map((item) => (
                  <a
                    key={item.id}
                    href={item.href}
                    className="flex items-center space-x-3 px-3 py-2 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                    onClick={onClose}
                  >
                    {/* Icon would go here */}
                    <span className="font-medium">{item.label}</span>
                  </a>
                ))}
              </div>
            </nav>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
```

---

## 🔐 Authentication & Authorization

### Auth Context
```tsx
// File: src/contexts/AuthContext.tsx
import React, { createContext, useContext, useReducer, useEffect } from 'react';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  permissions: string[];
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
}

type AuthAction =
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; token: string } }
  | { type: 'LOGOUT' }
  | { type: 'SET_LOADING'; payload: boolean };

const initialState: AuthState = {
  user: null,
  token: localStorage.getItem('token'),
  isAuthenticated: false,
  loading: true,
};

const authReducer = (state: AuthState, action: AuthAction): AuthState => {
  switch (action.type) {
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        loading: false,
      };
    case 'LOGOUT':
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        loading: false,
      };
    case 'SET_LOADING':
      return {
        ...state,
        loading: action.payload,
      };
    default:
      return state;
  }
};

const AuthContext = createContext<{
  state: AuthState;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
} | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      // Verify token and get user info
      verifyToken(token);
    } else {
      dispatch({ type: 'SET_LOADING', payload: false });
    }
  }, []);

  const verifyToken = async (token: string) => {
    try {
      const response = await fetch('/api/v1/auth/verify', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const user = await response.json();
        dispatch({ type: 'LOGIN_SUCCESS', payload: { user, token } });
      } else {
        localStorage.removeItem('token');
        dispatch({ type: 'LOGOUT' });
      }
    } catch (error) {
      localStorage.removeItem('token');
      dispatch({ type: 'LOGOUT' });
    }
  };

  const login = async (username: string, password: string) => {
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        const { user, token } = await response.json();
        localStorage.setItem('token', token);
        dispatch({ type: 'LOGIN_SUCCESS', payload: { user, token } });
      } else {
        throw new Error('Invalid credentials');
      }
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    dispatch({ type: 'LOGOUT' });
  };

  return (
    <AuthContext.Provider value={{ state, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

---

## 🚀 Build & Deployment

### Vite Configuration
```ts
// File: vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          charts: ['chart.js', 'react-chartjs-2', 'd3'],
          ui: ['@headlessui/react', 'framer-motion'],
        },
      },
    },
  },
});
```

### Docker Configuration
```dockerfile
# File: Dockerfile.frontend
FROM node:18-alpine as builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### Nginx Configuration
```nginx
# File: nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;

        # Gzip compression
        gzip on;
        gzip_vary on;
        gzip_min_length 1024;
        gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

        # API proxy
        location /api/ {
            proxy_pass http://backend:8080/api/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket proxy
        location /ws/ {
            proxy_pass http://backend:8080/ws/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # React Router support
        location / {
            try_files $uri $uri/ /index.html;
        }

        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
```

This comprehensive frontend specification provides a complete foundation for building the MUSAFIR central web UI with React, TypeScript, and modern web technologies. The architecture supports real-time updates, responsive design, and modular components for EDR, XDR, and SIEM functionality.
          </tbody>
        </table>

        {/* Pagination */}
        <div className="bg-white dark:bg-gray-800 px-4 py-3 border-t border-gray-200 dark:border-gray-700 sm:px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-700 dark:text-gray-300">
                Showing {pageIndex * pageSize + 1} to {Math.min((pageIndex + 1) * pageSize, endpoints.length)} of {endpoints.length} results
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => previousPage()}
                disabled={!canPreviousPage}
                className="px-3 py-1 text-sm border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Previous
              </button>
              <button
                onClick={() => nextPage()}
                disabled={!canNextPage}
                className="px-3 py-1 text-sm border border-gray-300 rounded-md disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
```

---

## 🔍 XDR (Extended Detection & Response)

### XDR Dashboard
```tsx
// File: src/pages/xdr/XDRDashboard.tsx
import React, { useState } from 'react';
import { motion } from 'framer-motion';

import { AttackChainVisualization } from '../../components/xdr/AttackChainVisualization';
import { CrossPlatformCorrelation } from '../../components/xdr/CrossPlatformCorrelation';
import { ThreatIntelligence } from '../../components/xdr/ThreatIntelligence';
import { IncidentTimeline } from '../../components/xdr/IncidentTimeline';
import { AutomatedResponse } from '../../components/xdr/AutomatedResponse';

export const XDRDashboard: React.FC = () => {
  const [activeView, setActiveView] = useState('overview');

  const views = [
    { id: 'overview', label: 'Overview', icon: 'ChartBarIcon' },
    { id: 'attack-chains', label: 'Attack Chains', icon: 'LinkIcon' },
    { id: 'correlation', label: 'Cross-Platform', icon: 'GlobeAltIcon' },
    { id: 'threat-intel', label: 'Threat Intel', icon: 'ShieldCheckIcon' },
    { id: 'timeline', label: 'Timeline', icon: 'ClockIcon' },
    { id: 'response', label: 'Automated Response', icon: 'BoltIcon' },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-4">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Extended Detection & Response
          </h1>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Comprehensive threat detection across all security layers
          </p>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <nav className="px-6">
          <div className="flex space-x-8">
            {views.map((view) => (
              <button
                key={view.id}
                onClick={() => setActiveView(view.id)}
                className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeView === view.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <div className="flex items-center space-x-2">
                  {/* Icon would go here */}
                  <span>{view.label}</span>
                </div>
              </button>
            ))}
          </div>
        </nav>
      </div>

      {/* Main Content */}
      <main className="p-6">
        <motion.div
          key={activeView}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          {activeView === 'overview' && <XDROverview />}
          {activeView === 'attack-chains' && <AttackChainVisualization />}
          {activeView === 'correlation' && <CrossPlatformCorrelation />}
          {activeView === 'threat-intel' && <ThreatIntelligence />}
          {activeView === 'timeline' && <IncidentTimeline />}
          {activeView === 'response' && <AutomatedResponse />}
        </motion.div>
      </main>
    </div>
  );
};

// XDR Overview Component
const XDROverview: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Campaigns</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">7</p>
            </div>
            <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <span className="text-sm text-red-600">+2 new this week</span>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Correlated Events</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">1,247</p>
            </div>
            <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <span className="text-sm text-blue-600">+15% from yesterday</span>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">MITRE TTPs</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">23</p>
            </div>
            <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <span className="text-sm text-orange-600">5 new techniques</span>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Response Time</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">4.2m</p>
            </div>
            <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <span className="text-sm text-green-600">-30% improvement</span>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Attack Chain Preview */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Recent Attack Chains
          </h3>
          {/* Attack chain visualization preview */}
        </div>

        {/* Threat Intelligence Feed */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Threat Intelligence Feed
          </h3>
          {/* Threat intel feed */}
        </div>
      </div>
    </div>
  );
};
```

---

## 📈 SIEM (Security Information & Event Management)

### SIEM Dashboard
```tsx
// File: src/pages/siem/SIEMDashboard.tsx
import React, { useState } from 'react';
import { motion } from 'framer-motion';

import { LogAnalysis } from '../../components/siem/LogAnalysis';
import { ComplianceMonitoring } from '../../components/siem/ComplianceMonitoring';
import { EventCorrelation } from '../../components/siem/EventCorrelation';
import { ReportGeneration } from '../../components/siem/ReportGeneration';
import { AlertManagement } from '../../components/siem/AlertManagement';

export const SIEMDashboard: React.FC = () => {
  const [activeModule, setActiveModule] = useState('overview');

  const modules = [
    { id: 'overview', label: 'Overview', icon: 'HomeIcon' },
    { id: 'logs', label: 'Log Analysis', icon: 'DocumentTextIcon' },
    { id: 'correlation', label: 'Event Correlation', icon: 'PuzzlePieceIcon' },
    { id: 'compliance', label: 'Compliance', icon: 'ShieldCheckIcon' },
    { id: 'alerts', label: 'Alert Management', icon: 'BellIcon' },
    { id: 'reports', label: 'Reports', icon: 'DocumentChartBarIcon' },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-4">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Security Information & Event Management
          </h1>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Centralized security monitoring and compliance management
          </p>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 min-h-screen">
          <div className="p-4">
            <div className="space-y-2">
              {modules.map((module) => (
                <button
                  key={module.id}
                  onClick={() => setActiveModule(module.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-left transition-colors ${
                    activeModule === module.id
                      ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                  }`}
                >
                  {/* Icon would go here */}
                  <span className="font-medium">{module.label}</span>
                </button>
              ))}
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          <motion.div
            key={activeModule}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            {activeModule === 'overview' && <SIEMOverview />}
            {activeModule === 'logs' && <LogAnalysis />}
            {activeModule === 'correlation' && <EventCorrelation />}
            {activeModule === 'compliance' && <ComplianceMonitoring />}
            {activeModule === 'alerts' && <AlertManagement />}
            {activeModule === 'reports' && <ReportGeneration />}
          </motion.div>
        </main>
      </div>
    </div>
  );
};

// SIEM Overview Component
const SIEMOverview: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Compliance Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">SOC 2 Compliance</p>
              <p className="text-2xl font-bold text-green-600">98.5%</p>
            </div>
            <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-green-500 h-2 rounded-full" style={{ width: '98.5%' }}></div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">GDPR Compliance</p>
              <p className="text-2xl font-bold text-yellow-600">85.2%</p>
            </div>
            <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-yellow-500 h-2 rounded-full" style={{ width: '85.2%' }}></div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">HIPAA Compliance</p>
              <p className="text-2xl font-bold text-blue-600">92.1%</p>
            </div>
            <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              {/* Icon */}
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-blue-500 h-2 rounded-full" style={{ width: '92.1%' }}></div>
            </div>
          </div>
        </div>
      </div>

      {/* Log Volume and Event Correlation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Log Volume (24h)
          </h3>
          {/* Log volume chart */}
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Event Correlation Rules
          </h3>
          {/* Correlation rules status */}
        </div>
      </div>
    </div>
  );
};
```

---

## 🔧 Component Library

### Shared Components
```tsx
// File: src/components/common/DataTable.tsx
import React from 'react';
import { useTable, useSortBy, useFilters, usePagination, Column } from 'react-table';

interface DataTableProps<T extends object> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  onRowClick?: (row: T) => void;
  selectedRowId?: string;
  pageSize?: number;
}

export function DataTable<T extends object>({
  columns,
  data,
  loading = false,
  onRowClick,
  selectedRowId,
  pageSize = 10,
}: DataTableProps<T>) {
  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    page,
    prepareRow,
    canPreviousPage,
    canNextPage,
    pageOptions,
    pageCount,
    gotoPage,
    nextPage,
    previousPage,
    setPageSize: setTablePageSize,
    state: { pageIndex, pageSize: currentPageSize },
  } = useTable(
    {
      columns,
      data,
      initialState: { pageIndex: 0, pageSize },
    },
    useFilters,
    useSortBy,
    usePagination
  );

  if (loading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-gray-200 rounded mb-4"></div>
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-12 bg-gray-200 rounded"></div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
      <div className="overflow-x-auto">
        <table {...getTableProps()} className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            {headerGroups.map(headerGroup => (
              <tr {...headerGroup.getHeaderGroupProps()}>
                {headerGroup.headers.map(column => (
                  <th
                    {...column.getHeaderProps(column.getSortByToggleProps())}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                  >
                    <div className="flex items-center space-x-1">
                      <span>{column.render('Header')}</span>
                      {column.isSorted ? (
                        column.isSortedDesc ? (
                          <span>↓</span>
                        ) : (
                          <span>↑</span>
                        )
                      ) : (
                        <span className="text-gray-400">↕</span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody {...getTableBodyProps()} className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {page.map(row => {
              prepareRow(row);
              const isSelected = selectedRowId && (row.original as any).id === selectedRowId;
              return (
                <tr
                  {...row.getRowProps()}
                  className={`hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors ${
                    isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                  onClick={() => onRowClick?.(row.original)}
                >
                  {row.cells.map(cell => (
                    <td {...cell.getCellProps()} className="px-6 py-4 whitespace-nowrap">
                      {cell.render('Cell')}
                    </td>
                  ))}
                </tr>
              );
            })}
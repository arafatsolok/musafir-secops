import React, { useState, useRef } from 'react';
import {
  Upload, Download, FileText, AlertCircle, CheckCircle,
  Users, X, Eye, RefreshCw, FileSpreadsheet, Database,
  AlertTriangle, Info, Check, Clock
} from 'lucide-react';
import { userService, BulkImportJob, CreateUserRequest } from '../services/users';

interface ImportPreview {
  valid: CreateUserRequest[];
  invalid: { row: number; data: any; errors: string[] }[];
  duplicates: { row: number; data: any; existing: string }[];
}

interface ImportStats {
  totalRows: number;
  validRows: number;
  invalidRows: number;
  duplicateRows: number;
  processed: number;
  successful: number;
  failed: number;
}

const BulkUserImport: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'import' | 'export' | 'jobs'>('import');
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importStats, setImportStats] = useState<ImportStats | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [importJobs, setImportJobs] = useState<BulkImportJob[]>([]);
  const [showPreview, setShowPreview] = useState(false);
  const [currentJob, setCurrentJob] = useState<BulkImportJob | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Export options
  const [exportFormat, setExportFormat] = useState<'csv' | 'excel'>('csv');
  const [exportFilters, setExportFilters] = useState({
    status: 'all',
    role: 'all',
    department: 'all',
    includeInactive: false
  });

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleFileSelect(files[0]);
    }
  };

  const handleFileSelect = (selectedFile: File) => {
    const allowedTypes = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    
    if (!allowedTypes.includes(selectedFile.type)) {
      alert('Please select a CSV or Excel file');
      return;
    }
    
    setFile(selectedFile);
    parseFile(selectedFile);
  };

  const parseFile = async (file: File) => {
    setIsProcessing(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await userService.previewBulkImport(formData);
      if (response.success) {
        setImportPreview(response.data);
        calculateStats(response.data);
        setShowPreview(true);
      }
    } catch (error) {
      console.error('Error parsing file:', error);
      alert('Error parsing file. Please check the format and try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  const calculateStats = (preview: ImportPreview) => {
    const stats: ImportStats = {
      totalRows: preview.valid.length + preview.invalid.length + preview.duplicates.length,
      validRows: preview.valid.length,
      invalidRows: preview.invalid.length,
      duplicateRows: preview.duplicates.length,
      processed: 0,
      successful: 0,
      failed: 0
    };
    setImportStats(stats);
  };

  const handleImport = async () => {
    if (!file || !importPreview) return;
    
    setIsProcessing(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('options', JSON.stringify({
        skipDuplicates: true,
        validateOnly: false,
        sendWelcomeEmail: true
      }));
      
      const response = await userService.bulkImportUsers(formData);
      if (response.success) {
        setCurrentJob(response.data);
        loadImportJobs();
        setShowPreview(false);
        setFile(null);
        setImportPreview(null);
        alert('Import job started successfully!');
      }
    } catch (error) {
      console.error('Error starting import:', error);
      alert('Error starting import. Please try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleExport = async () => {
    setIsProcessing(true);
    try {
      const response = await userService.exportUsers({
        format: exportFormat,
        filters: exportFilters
      });
      
      if (response.success && response.data) {
        // Create download link
        const blob = new Blob([response.data], {
          type: exportFormat === 'csv' ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `users_export_${new Date().toISOString().split('T')[0]}.${exportFormat}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error exporting users:', error);
      alert('Error exporting users. Please try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  const loadImportJobs = async () => {
    try {
      const response = await userService.getBulkImportJobs({ page: 1, limit: 20 });
      if (response.success) {
        setImportJobs(response.data);
      }
    } catch (error) {
      console.error('Error loading import jobs:', error);
    }
  };

  const getJobStatusColor = (status: BulkImportJob['status']) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-100';
      case 'failed': return 'text-red-600 bg-red-100';
      case 'processing': return 'text-blue-600 bg-blue-100';
      case 'pending': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getJobStatusIcon = (status: BulkImportJob['status']) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4" />;
      case 'failed': return <AlertCircle className="w-4 h-4" />;
      case 'processing': return <RefreshCw className="w-4 h-4 animate-spin" />;
      case 'pending': return <Clock className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  React.useEffect(() => {
    loadImportJobs();
  }, []);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Bulk User Management</h1>
          <p className="text-gray-600">Import and export users in bulk using CSV or Excel files</p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'import', name: 'Import Users', icon: Upload },
            { id: 'export', name: 'Export Users', icon: Download },
            { id: 'jobs', name: 'Import Jobs', icon: Database }
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

      {/* Import Tab */}
      {activeTab === 'import' && (
        <div className="space-y-6">
          {/* File Upload Area */}
          <div className="bg-white rounded-lg shadow border p-6">
            <h3 className="text-lg font-semibold mb-4">Upload User Data</h3>
            
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                dragActive
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-300 hover:border-gray-400'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <div className="space-y-4">
                <div className="flex justify-center">
                  <FileSpreadsheet className="w-12 h-12 text-gray-400" />
                </div>
                <div>
                  <p className="text-lg font-medium text-gray-900">
                    Drop your CSV or Excel file here
                  </p>
                  <p className="text-gray-500">or click to browse</p>
                </div>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Choose File
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.xlsx,.xls"
                  onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
                  className="hidden"
                />
              </div>
            </div>

            {file && (
              <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <FileText className="w-5 h-5 text-gray-500" />
                    <div>
                      <p className="font-medium text-gray-900">{file.name}</p>
                      <p className="text-sm text-gray-500">
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setFile(null);
                      setImportPreview(null);
                      setShowPreview(false);
                    }}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Import Preview */}
          {showPreview && importPreview && importStats && (
            <div className="bg-white rounded-lg shadow border p-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold">Import Preview</h3>
                <button
                  onClick={() => setShowPreview(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-blue-600">Total Rows</p>
                      <p className="text-2xl font-bold text-blue-900">{importStats.totalRows}</p>
                    </div>
                    <Users className="w-8 h-8 text-blue-600" />
                  </div>
                </div>

                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-green-600">Valid</p>
                      <p className="text-2xl font-bold text-green-900">{importStats.validRows}</p>
                    </div>
                    <CheckCircle className="w-8 h-8 text-green-600" />
                  </div>
                </div>

                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-red-600">Invalid</p>
                      <p className="text-2xl font-bold text-red-900">{importStats.invalidRows}</p>
                    </div>
                    <AlertCircle className="w-8 h-8 text-red-600" />
                  </div>
                </div>

                <div className="bg-yellow-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-yellow-600">Duplicates</p>
                      <p className="text-2xl font-bold text-yellow-900">{importStats.duplicateRows}</p>
                    </div>
                    <AlertTriangle className="w-8 h-8 text-yellow-600" />
                  </div>
                </div>
              </div>

              {/* Invalid Rows */}
              {importPreview.invalid.length > 0 && (
                <div className="mb-6">
                  <h4 className="text-md font-semibold text-red-600 mb-3">Invalid Rows</h4>
                  <div className="bg-red-50 rounded-lg p-4 max-h-64 overflow-y-auto">
                    {importPreview.invalid.slice(0, 10).map((item, index) => (
                      <div key={index} className="mb-2 p-2 bg-white rounded border">
                        <p className="text-sm font-medium text-red-800">Row {item.row}</p>
                        <ul className="text-sm text-red-600 list-disc list-inside">
                          {item.errors.map((error, i) => (
                            <li key={i}>{error}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                    {importPreview.invalid.length > 10 && (
                      <p className="text-sm text-red-600 mt-2">
                        ... and {importPreview.invalid.length - 10} more invalid rows
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex justify-end space-x-3">
                <button
                  onClick={() => setShowPreview(false)}
                  className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleImport}
                  disabled={importStats.validRows === 0 || isProcessing}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isProcessing ? 'Starting Import...' : `Import ${importStats.validRows} Users`}
                </button>
              </div>
            </div>
          )}

          {/* Template Download */}
          <div className="bg-white rounded-lg shadow border p-6">
            <h3 className="text-lg font-semibold mb-4">Download Template</h3>
            <p className="text-gray-600 mb-4">
              Download a template file to ensure your data is in the correct format.
            </p>
            <div className="flex space-x-3">
              <button
                onClick={() => {
                  // Download CSV template
                  const csvContent = 'username,email,firstName,lastName,department,role,phone,location\n' +
                    'john.doe,john.doe@company.com,John,Doe,IT,User,+1-555-0123,New York\n' +
                    'jane.smith,jane.smith@company.com,Jane,Smith,HR,Manager,+1-555-0124,Los Angeles';
                  
                  const blob = new Blob([csvContent], { type: 'text/csv' });
                  const url = window.URL.createObjectURL(blob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = 'user_import_template.csv';
                  document.body.appendChild(link);
                  link.click();
                  document.body.removeChild(link);
                  window.URL.revokeObjectURL(url);
                }}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
              >
                <Download className="w-4 h-4 mr-2" />
                CSV Template
              </button>
              <button
                onClick={() => {
                  // In a real implementation, this would generate an Excel template
                  alert('Excel template download would be implemented here');
                }}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                <Download className="w-4 h-4 mr-2" />
                Excel Template
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Export Tab */}
      {activeTab === 'export' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow border p-6">
            <h3 className="text-lg font-semibold mb-4">Export Users</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Export Options */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Export Format
                  </label>
                  <select
                    value={exportFormat}
                    onChange={(e) => setExportFormat(e.target.value as 'csv' | 'excel')}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="csv">CSV</option>
                    <option value="excel">Excel</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    User Status
                  </label>
                  <select
                    value={exportFilters.status}
                    onChange={(e) => setExportFilters({...exportFilters, status: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Status</option>
                    <option value="active">Active Only</option>
                    <option value="inactive">Inactive Only</option>
                    <option value="locked">Locked Only</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Role Filter
                  </label>
                  <select
                    value={exportFilters.role}
                    onChange={(e) => setExportFilters({...exportFilters, role: e.target.value})}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Roles</option>
                    <option value="admin">Admin</option>
                    <option value="user">User</option>
                    <option value="manager">Manager</option>
                  </select>
                </div>

                <div>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={exportFilters.includeInactive}
                      onChange={(e) => setExportFilters({...exportFilters, includeInactive: e.target.checked})}
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="ml-2 text-sm text-gray-700">Include inactive users</span>
                  </label>
                </div>
              </div>

              {/* Export Preview */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="text-sm font-medium text-gray-700 mb-3">Export Preview</h4>
                <div className="space-y-2 text-sm text-gray-600">
                  <p>Format: {exportFormat.toUpperCase()}</p>
                  <p>Estimated records: ~150 users</p>
                  <p>Columns: Username, Email, Name, Department, Role, Status, Last Login</p>
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={handleExport}
                disabled={isProcessing}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isProcessing ? (
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Download className="w-4 h-4 mr-2" />
                )}
                {isProcessing ? 'Exporting...' : 'Export Users'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Jobs Tab */}
      {activeTab === 'jobs' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow border">
            <div className="p-6 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-semibold">Import Jobs</h3>
                <button
                  onClick={loadImportJobs}
                  className="flex items-center px-4 py-2 text-blue-600 hover:bg-blue-50 rounded-lg"
                >
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Refresh
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Job ID
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      File Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Progress
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {importJobs.map((job) => (
                    <tr key={job.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                        {job.id}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {job.fileName}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${getJobStatusColor(job.status)}`}>
                          {getJobStatusIcon(job.status)}
                          <span className="ml-1">{job.status}</span>
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {job.processedCount}/{job.totalCount}
                        {job.totalCount > 0 && (
                          <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                            <div
                              className="bg-blue-600 h-2 rounded-full"
                              style={{ width: `${(job.processedCount / job.totalCount) * 100}%` }}
                            ></div>
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(job.createdAt).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button
                          onClick={() => setCurrentJob(job)}
                          className="text-blue-600 hover:text-blue-900"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Job Details Modal */}
      {currentJob && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Import Job Details</h3>
              <button
                onClick={() => setCurrentJob(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Job ID</label>
                  <p className="text-sm text-gray-900 font-mono">{currentJob.id}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${getJobStatusColor(currentJob.status)}`}>
                    {getJobStatusIcon(currentJob.status)}
                    <span className="ml-1">{currentJob.status}</span>
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">File Name</label>
                  <p className="text-sm text-gray-900">{currentJob.fileName}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Created By</label>
                  <p className="text-sm text-gray-900">{currentJob.createdBy}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Total Records</label>
                  <p className="text-sm text-gray-900">{currentJob.totalCount}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Processed</label>
                  <p className="text-sm text-gray-900">{currentJob.processedCount}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Successful</label>
                  <p className="text-sm text-green-600">{currentJob.successCount}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Failed</label>
                  <p className="text-sm text-red-600">{currentJob.errorCount}</p>
                </div>
              </div>
              
              {currentJob.errorDetails && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Error Details</label>
                  <div className="mt-1 p-3 bg-red-50 rounded-lg">
                    <pre className="text-sm text-red-800 whitespace-pre-wrap">{currentJob.errorDetails}</pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BulkUserImport;
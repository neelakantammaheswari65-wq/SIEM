import React, { useState, useEffect } from 'react';
import { useSIEM } from '../../context/SIEMContext';
import { User } from '../../types/siem';
import { api } from '../../services/apiClient';
import { siemEngine, SEED_USERS } from '../../services/siemEngine';
import {
  Users,
  Search,
  Filter,
  Plus,
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  ChevronRight,
  Database,
  Building,
  UserCheck,
  UserX,
  ExternalLink,
} from 'lucide-react';

export const UsersView: React.FC = () => {
  const {
    users,
    setUsers,
    riskScores,
    setActiveTab,
    setSelectedUser,
    currentUser,
    refreshState,
    addToast,
  } = useSIEM();

  const [search, setSearch] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('ALL');
  const [roleFilter, setRoleFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(false);

  // Dataset segmentation
  const [datasetMode, setDatasetMode] = useState<'production' | 'demo'>('production');
  const [demoPage, setDemoPage] = useState(1);
  const [demoTotal, setDemoTotal] = useState(1000);
  const [demoTotalPages, setDemoTotalPages] = useState(20);
  const [totalProductionCount, setTotalProductionCount] = useState(0);

  // Modal State for Manual Creation
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [employeeId, setEmployeeId] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [department, setDepartment] = useState('Engineering');
  const [designation, setDesignation] = useState('Software Engineer');
  const [clearanceLevel, setClearanceLevel] = useState('STANDARD');
  const [status, setStatus] = useState('ACTIVE');
  const [password, setPassword] = useState('password123');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  // Suspend State
  const [employeeToDisable, setEmployeeToDisable] = useState<User | null>(null);
  const [isDisabling, setIsDisabling] = useState(false);

  const isAdmin = currentUser.role === 'ADMIN';
  const isAnalyst = currentUser.role === 'SECURITY_ANALYST';
  const canViewEmployees = isAdmin || isAnalyst;

  const loadEmployees = async (mode: 'production' | 'demo' = datasetMode, page: number = demoPage) => {
    if (!canViewEmployees) return;
    setIsLoading(true);
    try {
      const res = await api.employees.list({
        dataset: mode,
        page: mode === 'demo' ? page : 1,
        limit: mode === 'demo' ? 50 : 200,
        search: search.trim() ? search : undefined,
        department: departmentFilter !== 'ALL' ? departmentFilter : undefined,
      });
      const list = res.employees || res.users || [];
      if (list && list.length > 0) {
        setUsers(list);
        if (res.totalProduction !== undefined) setTotalProductionCount(res.totalProduction);
        if (res.totalDemo !== undefined) setDemoTotal(res.totalDemo);
        if (res.totalPages !== undefined) setDemoTotalPages(res.totalPages);
      } else {
        const fallback = (siemEngine.users && siemEngine.users.length > 0) ? siemEngine.users : SEED_USERS;
        setUsers([...fallback]);
      }
    } catch (err: any) {
      const fallbackList = (siemEngine.users && siemEngine.users.length > 0) ? siemEngine.users : SEED_USERS;
      setUsers([...fallbackList]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (canViewEmployees) {
      loadEmployees(datasetMode, demoPage);
    }
  }, [canViewEmployees, datasetMode, demoPage, departmentFilter]);

  const handleOpenModal = () => {
    setEmployeeId('');
    setFullName('');
    setEmail('');
    setDepartment('Engineering');
    setDesignation('Software Engineer');
    setClearanceLevel('STANDARD');
    setStatus('ACTIVE');
    setPassword('password123');
    setModalError(null);
    setIsModalOpen(true);
  };

  const handleCreateEmployee = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);

    const cleanEmpId = employeeId.trim();
    const cleanName = fullName.trim();
    const cleanMail = email.trim();

    if (!cleanEmpId || !cleanName || !cleanMail) {
      setModalError('All fields marked * are required.');
      return;
    }

    setIsSubmitting(true);
    try {
      await api.employees.create({
        employeeId: cleanEmpId,
        fullName: cleanName,
        email: cleanMail,
        department: department.trim(),
        designation: designation.trim(),
        clearanceLevel,
        status,
        password,
      });

      addToast({
        title: 'Success',
        message: 'Employee created successfully',
        severity: 'LOW',
      });

      setIsModalOpen(false);
      setDatasetMode('production');
      await loadEmployees('production', 1);
      refreshState();
    } catch (err: any) {
      setModalError(err.message || 'Failed to create employee record');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConfirmDisable = async () => {
    if (!employeeToDisable) return;
    setIsDisabling(true);
    try {
      const newStatus = employeeToDisable.status === 'SUSPENDED' ? 'ACTIVE' : 'SUSPENDED';
      await api.employees.updateStatus(employeeToDisable.id, newStatus);
      addToast({
        title: 'Status Updated',
        message: `Employee ${employeeToDisable.fullName} is now ${newStatus}`,
        severity: 'LOW',
      });
      setEmployeeToDisable(null);
      await loadEmployees(datasetMode, demoPage);
      refreshState();
    } catch (err: any) {
      addToast({
        title: 'Update Failed',
        message: err.message || 'Error updating status',
        severity: 'HIGH',
      });
    } finally {
      setIsDisabling(false);
    }
  };

  // Metric counts
  const totalEmployeesCount = datasetMode === 'demo' ? demoTotal : (totalProductionCount || users.length);
  const highRiskCount = users.filter((u) => {
    const s = riskScores.find((r) => r.userId === u.id)?.finalScore || 0;
    return s >= 50;
  }).length;
  const activeCount = users.filter((u) => u.status === 'ACTIVE').length;

  // Filtered employees
  const filteredUsers = users.filter((u) => {
    if (!u) return false;
    const matchesSearch =
      (u.fullName || '').toLowerCase().includes(search.toLowerCase()) ||
      (u.username || '').toLowerCase().includes(search.toLowerCase()) ||
      (u.email || '').toLowerCase().includes(search.toLowerCase()) ||
      (u.employeeId || '').toLowerCase().includes(search.toLowerCase()) ||
      (u.department || '').toLowerCase().includes(search.toLowerCase());

    const matchesDept = departmentFilter === 'ALL' || u.department === departmentFilter;
    const matchesRole = roleFilter === 'ALL' || u.role === roleFilter;
    const matchesStatus = statusFilter === 'ALL' || u.status === statusFilter;

    const userRisk = riskScores.find((r) => r.userId === u.id)?.finalScore || 0;
    const userRiskLevel = userRisk >= 75 ? 'CRITICAL' : userRisk >= 50 ? 'HIGH' : userRisk >= 25 ? 'MEDIUM' : 'LOW';
    const matchesRisk = riskFilter === 'ALL' || userRiskLevel === riskFilter;

    return matchesSearch && matchesDept && matchesRole && matchesStatus && matchesRisk;
  });

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto text-slate-200">
      {/* Top Section: Employee Directory */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Employee Directory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise identity directory with behavioral risk scoring and clearance boundaries.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Dataset Segmentation Selector */}
          <div className="flex items-center bg-[#0D1424] border border-[#22304A] rounded-lg p-0.5 text-xs">
            <button
              onClick={() => {
                setDatasetMode('production');
                loadEmployees('production', 1);
              }}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                datasetMode === 'production'
                  ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Production
            </button>
            <button
              onClick={() => {
                setDatasetMode('demo');
                loadEmployees('demo', 1);
              }}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                datasetMode === 'demo'
                  ? 'bg-[#111A2C] text-white font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              1,000 Demo Dataset
            </button>
          </div>

          {isAdmin && (
            <button
              onClick={handleOpenModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white text-xs font-semibold transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Employee</span>
            </button>
          )}
        </div>
      </div>

      {/* 4 Metrics: Total Employees, High Risk, Active, Demo Employees */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Employees */}
        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            TOTAL EMPLOYEES
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            {totalEmployeesCount.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {datasetMode === 'demo' ? 'Synthetic Demo Records' : 'Organization Directory'}
          </div>
        </div>

        {/* High Risk */}
        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            HIGH RISK
          </div>
          <div className="text-2xl font-bold font-mono text-[#FF5C6C] mt-2">
            {highRiskCount}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Risk score &gt;= 50
          </div>
        </div>

        {/* Active */}
        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            ACTIVE STATUS
          </div>
          <div className="text-2xl font-bold font-mono text-[#20C997] mt-2">
            {activeCount}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Enabled credentials
          </div>
        </div>

        {/* Demo Employees */}
        <div className="soc-card p-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            DEMO DATASET
          </div>
          <div className="text-2xl font-bold font-mono text-[#8B7CFF] mt-2">
            1,000
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Isolated benchmark pool
          </div>
        </div>
      </div>

      {/* Filter Bar: Search, Department, Role, Risk */}
      <div className="soc-card p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search employee, ID, email..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-[#5B8CFF]"
          />
        </div>

        <div>
          <select
            value={departmentFilter}
            onChange={(e) => setDepartmentFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Departments</option>
            <option value="Engineering">Engineering</option>
            <option value="Finance">Finance</option>
            <option value="Human Resources">Human Resources</option>
            <option value="Sales">Sales</option>
            <option value="Executive">Executive</option>
            <option value="Legal">Legal</option>
          </select>
        </div>

        <div>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Roles</option>
            <option value="ADMIN">ADMIN</option>
            <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
            <option value="EMPLOYEE">EMPLOYEE</option>
          </select>
        </div>

        <div>
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-[#5B8CFF]"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical (&gt;= 75)</option>
            <option value="HIGH">High (50-74)</option>
            <option value="MEDIUM">Medium (25-49)</option>
            <option value="LOW">Low (&lt; 25)</option>
          </select>
        </div>
      </div>

      {/* Employee Table: Employee, Department, Role, Status, Risk Score, Last Activity, Actions */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#22304A] bg-[#0D1424] text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Employee</th>
                <th className="py-3 px-4">Department</th>
                <th className="py-3 px-4">Role</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Last Activity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#22304A]">
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    No employees matched the criteria.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => {
                  const userRisk = riskScores.find((r) => r.userId === u.id)?.finalScore || 0;
                  const isSuspended = u.status === 'SUSPENDED';

                  const riskColor =
                    userRisk >= 75
                      ? 'text-[#FF5C6C]'
                      : userRisk >= 50
                      ? 'text-[#FFB020]'
                      : userRisk >= 25
                      ? 'text-[#5B8CFF]'
                      : 'text-[#20C997]';

                  return (
                    <tr
                      key={u.id}
                      onClick={() => {
                        setSelectedUser(u);
                        setActiveTab('risk');
                      }}
                      className="hover:bg-[#0D1424] transition-colors cursor-pointer"
                    >
                      {/* Employee Column */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-[#5B8CFF]/15 border border-[#5B8CFF]/30 text-[#5B8CFF] flex items-center justify-center font-bold text-xs shrink-0">
                            {u.fullName.charAt(0)}
                          </div>
                          <div>
                            <div className="font-semibold text-white flex items-center gap-2">
                              <span>{u.fullName}</span>
                              {u.isDemo && (
                                <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                  DEMO
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-400">
                              {u.employeeId || `EMP-${u.id}`} · {u.email}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Department */}
                      <td className="py-3 px-4 text-slate-300">
                        {u.department}
                      </td>

                      {/* Role */}
                      <td className="py-3 px-4 text-slate-300">
                        <div className="font-medium text-white">{u.role}</div>
                        <div className="text-[10px] text-slate-400">{u.designation || 'Specialist'}</div>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4">
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${
                            isSuspended
                              ? 'bg-[#FF5C6C]/10 text-[#FF5C6C] border-[#FF5C6C]/30'
                              : 'bg-[#20C997]/10 text-[#20C997] border-[#20C997]/30'
                          }`}
                        >
                          {isSuspended ? 'Suspended' : 'Active'}
                        </span>
                      </td>

                      {/* Risk Score */}
                      <td className="py-3 px-4">
                        <div className="w-32">
                          <div className="flex justify-between font-mono text-xs">
                            <span className={`font-bold ${riskColor}`}>{userRisk}</span>
                            <span className="text-slate-500 text-[10px]">/ 100</span>
                          </div>
                          <div className="w-full bg-[#0D1424] rounded-full h-1.5 mt-1 border border-[#22304A]">
                            <div
                              className={`h-full rounded-full ${
                                userRisk >= 75
                                  ? 'bg-[#FF5C6C]'
                                  : userRisk >= 50
                                  ? 'bg-[#FFB020]'
                                  : userRisk >= 25
                                  ? 'bg-[#5B8CFF]'
                                  : 'bg-[#20C997]'
                              }`}
                              style={{ width: `${Math.min(userRisk, 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Last Activity */}
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        {u.lastLogin ? new Date(u.lastLogin).toLocaleTimeString() : 'Recent'}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right space-x-1.5">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedUser(u);
                            setActiveTab('risk');
                          }}
                          className="px-2.5 py-1 rounded bg-[#0D1424] hover:bg-[#1E2B42] text-xs text-[#5B8CFF] border border-[#22304A] cursor-pointer"
                        >
                          Profile
                        </button>

                        {isAdmin && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setEmployeeToDisable(u);
                            }}
                            className={`px-2.5 py-1 rounded text-xs border cursor-pointer ${
                              isSuspended
                                ? 'bg-[#20C997]/15 text-[#20C997] border-[#20C997]/30 hover:bg-[#20C997]/25'
                                : 'bg-[#FF5C6C]/15 text-[#FF5C6C] border-[#FF5C6C]/30 hover:bg-[#FF5C6C]/25'
                            }`}
                          >
                            {isSuspended ? 'Enable' : 'Suspend'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Demo Pagination if in demo mode */}
        {datasetMode === 'demo' && (
          <div className="p-3.5 bg-[#0D1424] border-t border-[#22304A] flex items-center justify-between text-xs text-slate-400">
            <span>Page {demoPage} of {demoTotalPages} ({demoTotal} demo employees)</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setDemoPage((p) => Math.max(1, p - 1))}
                disabled={demoPage <= 1}
                className="px-2.5 py-1 rounded bg-[#111A2C] border border-[#22304A] disabled:opacity-40 cursor-pointer text-white"
              >
                Prev
              </button>
              <button
                onClick={() => setDemoPage((p) => Math.min(demoTotalPages, p + 1))}
                disabled={demoPage >= demoTotalPages}
                className="px-2.5 py-1 rounded bg-[#111A2C] border border-[#22304A] disabled:opacity-40 cursor-pointer text-white"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Add Employee Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#22304A] pb-3">
              <h3 className="text-sm font-semibold text-white">Create Employee Record</h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            {modalError && (
              <div className="text-xs text-[#FF5C6C] bg-[#FF5C6C]/10 p-2 rounded border border-[#FF5C6C]/20">
                {modalError}
              </div>
            )}

            <form onSubmit={handleCreateEmployee} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Employee ID *</label>
                <input
                  type="text"
                  placeholder="e.g. EMP-9021"
                  value={employeeId}
                  onChange={(e) => setEmployeeId(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Full Name *</label>
                <input
                  type="text"
                  placeholder="e.g. Sarah Connor"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Email *</label>
                <input
                  type="email"
                  placeholder="sconnor@enterprise.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-slate-400 block mb-1">Department</label>
                  <select
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  >
                    <option value="Engineering">Engineering</option>
                    <option value="Finance">Finance</option>
                    <option value="Human Resources">Human Resources</option>
                    <option value="Sales">Sales</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Designation</label>
                  <input
                    type="text"
                    value={designation}
                    onChange={(e) => setDesignation(e.target.value)}
                    className="w-full bg-[#0D1424] border border-[#22304A] rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[#22304A]">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg bg-[#0D1424] text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-3.5 py-1.5 rounded-lg bg-[#5B8CFF] hover:bg-[#4a7cee] text-white font-semibold cursor-pointer"
                >
                  {isSubmitting ? 'Creating...' : 'Save Employee'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Suspend Confirmation Dialog */}
      {employeeToDisable && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#111A2C] border border-[#22304A] rounded-xl max-w-sm w-full p-5 space-y-4 shadow-2xl">
            <h3 className="text-sm font-semibold text-white">
              {employeeToDisable.status === 'SUSPENDED' ? 'Enable Credentials' : 'Suspend Employee'}
            </h3>
            <p className="text-xs text-slate-300">
              Are you sure you want to {employeeToDisable.status === 'SUSPENDED' ? 'reactivate' : 'suspend'}{' '}
              <strong className="text-white">{employeeToDisable.fullName}</strong>?
            </p>
            <div className="flex justify-end gap-2 pt-2 border-t border-[#22304A]">
              <button
                onClick={() => setEmployeeToDisable(null)}
                className="px-3 py-1.5 rounded-lg bg-[#0D1424] text-slate-300 text-xs cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDisable}
                disabled={isDisabling}
                className="px-3 py-1.5 rounded-lg bg-[#FF5C6C] hover:bg-[#e04e5d] text-white text-xs font-semibold cursor-pointer"
              >
                {isDisabling ? 'Updating...' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

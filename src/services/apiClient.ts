import {
  Alert,
  AuditLog,
  DemoFile,
  FileActivityRecord,
  Finding,
  MLAnomaly,
  NormalizedEvent,
  RiskScore,
  Rule,
  SecurityLog,
  SOCSummary,
  USBDevice,
  USBTransferRequest,
  User,
  UserRole,
} from '../types/siem';

const API_BASE = '/api';

export interface SOCSnapshot {
  summary: SOCSummary;
  alerts: Alert[];
  events: NormalizedEvent[];
  findings: Finding[];
  riskScores: RiskScore[];
  rules: Rule[];
  usbDevices: USBDevice[];
  usbTransfers: USBTransferRequest[];
  auditLogs: AuditLog[];
  mlAnomalies?: MLAnomaly[];
  employees?: User[];
}

export interface AINarrativeResponse {
  fallback: boolean;
  source: 'gemini_ai' | 'local_detection';
  message?: string;
  narrative: string;
  mitreTactics?: string[];
  recommendedActions?: string[];
}

class ApiClient {
  private token: string | null = null;
  private rateLimitCooldownUntil: number = 0;
  private isRateLimitedState: boolean = false;
  private rateLimitListeners: Set<(limited: boolean) => void> = new Set();

  constructor() {
    this.token = localStorage.getItem('siem_auth_token');
  }

  public setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('siem_auth_token', token);
    } else {
      localStorage.removeItem('siem_auth_token');
    }
  }

  public getToken(): string | null {
    const stored = typeof window !== 'undefined' ? localStorage.getItem('siem_auth_token') : null;
    if (stored) {
      this.token = stored;
      return stored;
    }
    return this.token;
  }

  public isRateLimited(): boolean {
    if (this.rateLimitCooldownUntil > Date.now()) {
      return true;
    }
    if (this.isRateLimitedState) {
      this.isRateLimitedState = false;
      this.notifyRateLimitChange(false);
    }
    return false;
  }

  public onRateLimitChange(listener: (limited: boolean) => void): () => void {
    this.rateLimitListeners.add(listener);
    return () => {
      this.rateLimitListeners.delete(listener);
    };
  }

  private notifyRateLimitChange(limited: boolean) {
    this.rateLimitListeners.forEach((listener) => {
      try {
        listener(limited);
      } catch {
        // ignore
      }
    });
  }

  private markRateLimited(seconds: number = 15) {
    this.rateLimitCooldownUntil = Date.now() + seconds * 1000;
    if (!this.isRateLimitedState) {
      this.isRateLimitedState = true;
      this.notifyRateLimitChange(true);
    }
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    // If currently rate-limited, avoid hitting the network and fast-fail gracefully
    if (this.isRateLimited()) {
      throw new Error('API temporarily rate-limited. Serving local SIEM detection data.');
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Set 8-second request timeout to prevent hanging connections
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    let response: Response;
    try {
      response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
        signal: controller.signal,
      });
    } catch (fetchErr: any) {
      clearTimeout(timeoutId);
      if (fetchErr.name === 'AbortError') {
        throw new Error(`Request to ${endpoint} timed out after 8s.`);
      }
      throw fetchErr;
    } finally {
      clearTimeout(timeoutId);
    }

    // Check for HTTP 429 or status indicating rate limit
    if (response.status === 429) {
      this.markRateLimited(20);
      throw new Error('Rate exceeded. Backing off network requests and using local telemetry.');
    }

    const contentType = response.headers.get('content-type') || '';
    const isJson = contentType.includes('application/json');

    if (!response.ok) {
      let errorMessage = `HTTP ${response.status} ${response.statusText}`;
      if (isJson) {
        try {
          const errorBody = await response.json();
          if (errorBody && errorBody.error) {
            errorMessage = errorBody.error;
          }
        } catch {
          // ignore json parse error
        }
      } else {
        try {
          const rawText = await response.text();
          if (rawText.toLowerCase().includes('rate exceeded') || rawText.toLowerCase().includes('quota exceeded')) {
            this.markRateLimited(20);
            errorMessage = 'Rate exceeded. Backing off network requests and using local telemetry.';
          } else if (rawText.length > 0 && rawText.length < 200) {
            errorMessage = rawText;
          }
        } catch {
          // ignore text parse error
        }
      }
      throw new Error(errorMessage);
    }

    // Handle 200 OK responses
    if (!isJson) {
      // If server returned non-JSON (e.g. HTML from SPA fallback), safely extract text without JSON.parse crash
      const rawText = await response.text();
      if (rawText.toLowerCase().includes('rate exceeded') || rawText.toLowerCase().includes('quota exceeded')) {
        this.markRateLimited(20);
        throw new Error('Rate exceeded. Using local SIEM telemetry.');
      }
      throw new Error(`Unexpected non-JSON response from server for ${endpoint}`);
    }

    return response.json() as Promise<T>;
  }

  // Authentication
  public auth = {
    login: (username: string, password: string) =>
      this.request<{ token: string; user: User; message: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),

    register: (userData: {
      username: string;
      email: string;
      password: string;
      fullName?: string;
      department?: string;
      role?: UserRole;
    }) =>
      this.request<{ token: string; user: User; message: string; abuseAlertGenerated?: boolean }>(
        '/auth/register',
        {
          method: 'POST',
          body: JSON.stringify(userData),
        }
      ),

    me: () => this.request<{ user: User }>('/auth/me'),
  };

  // Corporate Files & Download Monitoring
  public files = {
    list: () => this.request<{ files: DemoFile[] }>('/files'),
    get: (id: string) => this.request<{ file: DemoFile }>(`/files/${id}`),
    access: (id: string, action: 'OPEN' | 'VIEW' | 'DOWNLOAD' | 'REQUEST_ACCESS') =>
      this.request<{ success: boolean; message: string; file: DemoFile }>(`/files/${id}/access`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      }),
    download: (id: string) =>
      this.request<{ success: boolean; message: string; file: DemoFile; downloadUrl: string }>(
        `/files/${id}/download`,
        {
          method: 'POST',
        }
      ),
    myActivity: () => this.request<{ activities: FileActivityRecord[] }>('/my-activity'),
  };

  // Employees & Employee Management (Admin Only)
  public employees = {
    list: (params?: {
      dataset?: 'production' | 'demo' | 'all';
      page?: number;
      limit?: number;
      search?: string;
      department?: string;
    }) => {
      const q = new URLSearchParams();
      if (params?.dataset) q.set('dataset', params.dataset);
      if (params?.page) q.set('page', String(params.page));
      if (params?.limit) q.set('limit', String(params.limit));
      if (params?.search) q.set('search', params.search);
      if (params?.department) q.set('department', params.department);
      const queryStr = q.toString() ? `?${q.toString()}` : '';
      return this.request<{
        employees: User[];
        users?: User[];
        total?: number;
        page?: number;
        limit?: number;
        totalProduction?: number;
        totalDemo?: number;
        totalPages?: number;
        dataset?: string;
      }>(`/employees${queryStr}`);
    },
    create: (data: {
      employeeId: string;
      fullName: string;
      email: string;
      department: string;
      designation: string;
      clearanceLevel: string;
      status?: string;
      password?: string;
    }) =>
      this.request<{ message: string; employee: User }>('/employees', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    update: (id: string | number, data: Partial<User>) =>
      this.request<{ message: string; employee: User }>(`/employees/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    delete: (id: string | number, permanent?: boolean) =>
      this.request<{ message: string; employee?: User }>(`/employees/${id}${permanent ? '?permanent=true' : ''}`, {
        method: 'DELETE',
      }),
    updateStatus: (id: string | number, status: string) =>
      this.request<{ message: string; employee: User }>(`/employees/${id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
  };

  // Users & Employee Provisioning (Compatibility)
  public users = {
    list: () => this.request<{ users: User[]; employees?: User[] }>('/employees'),
    createEmployee: (data: {
      employeeId: string;
      fullName: string;
      email: string;
      department?: string;
      designation?: string;
      clearanceLevel?: string;
      status?: string;
      password?: string;
    }) =>
      this.request<{ message: string; employee: User }>('/employees', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    updateEmployeeStatus: (id: number | string, status: string) =>
      this.request<{ message: string; employee: User }>(`/employees/${id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    deleteEmployee: (id: number | string, permanent?: boolean) =>
      this.request<{ message: string; employee?: User }>(`/employees/${id}${permanent ? '?permanent=true' : ''}`, {
        method: 'DELETE',
      }),
  };

  // Platform Diagnostics & Health
  public health = {
    get: () => this.request<any>('/health'),
  };

  // SOC SIEM Endpoints
  public soc = {
    // Consolidated Single Snapshot endpoint (replaces 9-12 simultaneous HTTP calls)
    getSnapshot: () => this.request<SOCSnapshot & { snapshot?: SOCSnapshot }>('/soc/snapshot'),

    getSummary: () => this.request<{ summary: SOCSummary }>('/summary'),
    getAlerts: () => this.request<{ alerts: Alert[] }>('/alerts'),
    acknowledgeAlert: (alertId: string) =>
      this.request<{ message: string; alert: Alert }>(`/alerts/${alertId}/acknowledge`, {
        method: 'POST',
      }),
    resolveAlert: (alertId: string) =>
      this.request<{ message: string; alert: Alert }>(`/alerts/${alertId}/resolve`, {
        method: 'POST',
      }),
    falsePositiveAlert: (alertId: string) =>
      this.request<{ message: string; alert: Alert }>(`/alerts/${alertId}/false-positive`, {
        method: 'POST',
      }),
    getRules: () => this.request<{ rules: Rule[] }>('/rules'),
    createRule: (ruleData: Partial<Rule>) =>
      this.request<{ message: string; rule: Rule }>('/rules', {
        method: 'POST',
        body: JSON.stringify(ruleData),
      }),
    updateRule: (ruleId: number, updates: Partial<Rule>) =>
      this.request<{ message: string; rule: Rule }>(`/rules/${ruleId}`, {
        method: 'PUT',
        body: JSON.stringify(updates),
      }),
    getEvents: () => this.request<{ events: NormalizedEvent[] }>('/events'),
    getLogs: () => this.request<{ logs: SecurityLog[] }>('/logs'),
    getFindings: () => this.request<{ findings: Finding[] }>('/findings'),
    getRiskScores: () => this.request<{ riskScores: RiskScore[] }>('/risk/users'),
    recalculateRisk: () => this.request<{ message: string }>('/risk/recalculate', { method: 'POST' }),
    getMLAnomalies: () => this.request<{ anomalies: MLAnomaly[] }>('/ml/anomalies'),
    trainMLModel: () => this.request<{ message: string }>('/ml/train', { method: 'POST' }),
    getUSBDevices: () => this.request<{ usbDevices: USBDevice[] }>('/usb/devices'),
    toggleUSBAuth: (deviceId: string, authorized: boolean) =>
      this.request<{ message: string; device: USBDevice }>(`/usb/devices/${deviceId}/toggle-auth`, {
        method: 'POST',
        body: JSON.stringify({ authorized }),
      }),
    getUSBTransfers: () => this.request<{ transfers: USBTransferRequest[] }>('/usb/transfers'),
    requestUSBTransfer: (
      userId: number,
      deviceId: string,
      files: { name: string; sizeMb: number; sensitive: boolean; type: string }[]
    ) =>
      this.request<{ transfer: USBTransferRequest }>('/usb/transfers', {
        method: 'POST',
        body: JSON.stringify({ userId, deviceId, files }),
      }),
    getAuditLogs: () => this.request<{ auditLogs: AuditLog[] }>('/audit'),
    getSecurityEvents: () => this.request<{ securityEvents: any[] }>('/security-events'),
    injectScenario: (scenarioType: string) =>
      this.request<{ message: string }>('/scenarios/inject', {
        method: 'POST',
        body: JSON.stringify({ scenarioType }),
      }),
    seedDemo: () => this.request<{ message: string }>('/admin/seed', { method: 'POST' }),
    clearTelemetry: () => this.request<{ message: string }>('/admin/clear', { method: 'POST' }),
    testEndpoint: (endpoint: string) => this.request<any>(endpoint),

    // On-demand AI narrative (only called when user clicks the button)
    getAlertNarrative: (alertId: string) =>
      this.request<AINarrativeResponse>(`/soc/alerts/${alertId}/ai-narrative`, {
        method: 'POST',
      }),
  };
}

export const api = new ApiClient();

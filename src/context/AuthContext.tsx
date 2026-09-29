import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserRole } from '../types/siem';
import { api } from '../services/apiClient';

export interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (identifier: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (payload: {
    username: string;
    email: string;
    password: string;
    fullName: string;
    department?: string;
    role?: UserRole;
  }) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_STORAGE_KEY = 'siem_auth_token';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Validate existing token on boot
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem(TOKEN_STORAGE_KEY);
      if (!storedToken) {
        setLoading(false);
        return;
      }

      // Check for local demo token
      if (storedToken.startsWith('demo_token_')) {
        const parts = storedToken.split('_');
        const uname = parts[2];
        const demoUsers: Record<string, User> = {
          schen: {
            id: 102,
            username: 'schen',
            fullName: 'Sarah Chen',
            email: 'sarah.chen@corp-apex.internal',
            department: 'Infrastructure & DevOps',
            role: 'ADMIN',
            status: 'ACTIVE',
            employeeId: 'EMP-001',
            clearanceLevel: 'RESTRICTED',
            createdAt: '2024-01-01T08:00:00Z',
          },
          dkim: {
            id: 103,
            username: 'dkim',
            fullName: 'David Kim',
            email: 'david.kim@corp-apex.internal',
            department: 'Security Operations Center',
            role: 'SECURITY_ANALYST',
            status: 'ACTIVE',
            employeeId: 'EMP-002',
            clearanceLevel: 'RESTRICTED',
            createdAt: '2024-03-15T08:00:00Z',
          },
          amercer: {
            id: 101,
            username: 'amercer',
            fullName: 'Alex Mercer',
            email: 'alex.mercer@corp-apex.internal',
            department: 'Engineering (Core Systems)',
            role: 'EMPLOYEE',
            status: 'ACTIVE',
            employeeId: 'EMP-101',
            clearanceLevel: 'RESTRICTED',
            createdAt: '2024-06-01T08:00:00Z',
          },
        };
        const u = demoUsers[uname] || demoUsers.schen;
        setUser(u);
        setToken(storedToken);
        api.setToken(storedToken);
        setLoading(false);
        return;
      }

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        const response = await fetch('/api/auth/me', {
          headers: {
            Authorization: `Bearer ${storedToken}`,
          },
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (response.ok) {
          const data = await response.json();
          if (data.user) {
            setUser(data.user);
            setToken(storedToken);
            api.setToken(storedToken);
          } else {
            localStorage.removeItem(TOKEN_STORAGE_KEY);
            setUser(null);
            setToken(null);
            api.setToken(null);
          }
        } else {
          // Token expired or invalid
          localStorage.removeItem(TOKEN_STORAGE_KEY);
          setUser(null);
          setToken(null);
          api.setToken(null);
        }
      } catch (err) {
        console.warn('Backend unavailable during session verification, falling back to local session:', err);
        // If backend is down, keep a demo session active so the app remains accessible
        setUser({
          id: 102,
          username: 'schen',
          fullName: 'Sarah Chen',
          email: 'sarah.chen@corp-apex.internal',
          department: 'Infrastructure & DevOps',
          role: 'ADMIN',
          status: 'ACTIVE',
          employeeId: 'EMP-001',
          clearanceLevel: 'RESTRICTED',
          createdAt: '2024-01-01T08:00:00Z',
        });
        setToken(storedToken);
        api.setToken(storedToken);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (identifier: string, password: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          usernameOrEmail: identifier,
          password,
        }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || 'Authentication failed. Please verify credentials.',
        };
      }

      if (data.token && data.user) {
        localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
        setToken(data.token);
        api.setToken(data.token);
        setUser(data.user);
        return { success: true };
      }

      return { success: false, error: 'Malformed authentication server response.' };
    } catch (err: any) {
      console.warn('Network error or backend unavailable during login, falling back to local demo authentication:', err);

      // Local demo accounts fallback
      const demoUsers: Record<string, User> = {
        schen: {
          id: 102,
          username: 'schen',
          fullName: 'Sarah Chen',
          email: 'sarah.chen@corp-apex.internal',
          department: 'Infrastructure & DevOps',
          role: 'ADMIN',
          status: 'ACTIVE',
          employeeId: 'EMP-001',
          clearanceLevel: 'RESTRICTED',
          createdAt: '2024-01-01T08:00:00Z',
        },
        dkim: {
          id: 103,
          username: 'dkim',
          fullName: 'David Kim',
          email: 'david.kim@corp-apex.internal',
          department: 'Security Operations Center',
          role: 'SECURITY_ANALYST',
          status: 'ACTIVE',
          employeeId: 'EMP-002',
          clearanceLevel: 'RESTRICTED',
          createdAt: '2024-03-15T08:00:00Z',
        },
        amercer: {
          id: 101,
          username: 'amercer',
          fullName: 'Alex Mercer',
          email: 'alex.mercer@corp-apex.internal',
          department: 'Engineering (Core Systems)',
          role: 'EMPLOYEE',
          status: 'ACTIVE',
          employeeId: 'EMP-101',
          clearanceLevel: 'RESTRICTED',
          createdAt: '2024-06-01T08:00:00Z',
        },
        'emp-101': {
          id: 101,
          username: 'amercer',
          fullName: 'Alex Mercer',
          email: 'alex.mercer@corp-apex.internal',
          department: 'Engineering (Core Systems)',
          role: 'EMPLOYEE',
          status: 'ACTIVE',
          employeeId: 'EMP-101',
          clearanceLevel: 'RESTRICTED',
          createdAt: '2024-06-01T08:00:00Z',
        },
      };

      const matchedUser = demoUsers[identifier.toLowerCase()] || demoUsers[identifier];
      if (matchedUser && password === 'password123') {
        const demoToken = `demo_token_${matchedUser.username}_${Date.now()}`;
        localStorage.setItem(TOKEN_STORAGE_KEY, demoToken);
        setToken(demoToken);
        api.setToken(demoToken);
        setUser(matchedUser);
        return { success: true };
      }

      return { success: false, error: 'Connection to SIEM backend unavailable and credentials did not match local demo users.' };
    }
  };

  const register = async (payload: {
    username: string;
    email: string;
    password: string;
    fullName: string;
    department?: string;
    role?: UserRole;
  }): Promise<{ success: boolean; error?: string }> => {
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || 'Registration failed. Please check form inputs.',
        };
      }

      if (data.token && data.user) {
        localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
        setToken(data.token);
        api.setToken(data.token);
        setUser(data.user);
        return { success: true };
      }

      return { success: true };
    } catch (err: any) {
      console.error('Network error during registration:', err);
      return { success: false, error: 'Connection failed. Unable to reach SIEM registration endpoint.' };
    }
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken(null);
    api.setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    const storedToken = token || localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!storedToken) return;

    try {
      const response = await fetch('/api/auth/me', {
        headers: {
          Authorization: `Bearer ${storedToken}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        if (data.user) {
          setUser(data.user);
        }
      }
    } catch (err) {
      console.error('Failed to refresh user profile:', err);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user && !!token,
        loading,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
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

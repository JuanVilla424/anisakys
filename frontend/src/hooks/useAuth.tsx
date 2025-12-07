import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { apiClient } from '@/services/api';
import type { AuthState, User } from '@/types';

interface AuthContextType extends AuthState {
  login: (apiKey: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    token: null,
  });

  useEffect(() => {
    // Check for existing token on mount
    const token = apiClient.getToken();
    if (token) {
      setAuthState({
        user: {
          id: 'user-1',
          email: 'admin@anisakys.local',
          role: 'admin',
          apiKey: token,
        },
        isAuthenticated: true,
        token,
      });
    }
  }, []);

  const login = async (apiKey: string) => {
    try {
      await apiClient.login(apiKey);
      const user: User = {
        id: 'user-1',
        email: 'admin@anisakys.local',
        role: 'admin',
        apiKey,
      };
      setAuthState({
        user,
        isAuthenticated: true,
        token: apiKey,
      });
    } catch (error) {
      throw new Error('Invalid API key');
    }
  };

  const logout = () => {
    apiClient.logout();
    setAuthState({
      user: null,
      isAuthenticated: false,
      token: null,
    });
  };

  return (
    <AuthContext.Provider value={{ ...authState, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

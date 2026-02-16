import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Search,
  Database,
  FileText,
  Microscope,
  BarChart3,
  Settings,
  LogOut,
  Shield,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import clsx from 'clsx';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Scanner', href: '/scanner', icon: Search },
  { name: 'Sites', href: '/sites', icon: Database },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Research', href: '/research', icon: Microscope },
  { name: 'Threat Intel', href: '/threat-intel', icon: Shield },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export function Navbar() {
  const location = useLocation();
  const { user, logout } = useAuth();

  return (
    <nav className="border-b border-gray-300 bg-white">
      <div className="mx-auto max-w-[1600px] px-8">
        <div className="flex h-12 items-center justify-between">
          <div className="flex items-center gap-8">
            <Link to="/" className="text-sm font-medium text-gray-900">
              Anisakys
            </Link>
            <div className="flex gap-6">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    className={clsx(
                      'text-xs font-medium',
                      isActive ? 'text-gray-900' : 'text-gray-500 hover:text-gray-900'
                    )}
                  >
                    {item.name}
                  </Link>
                );
              })}
            </div>
          </div>
          {user && (
            <button
              onClick={logout}
              className="text-xs text-gray-500 hover:text-gray-900"
            >
              Logout
            </button>
          )}
        </div>
      </div>
    </nav>
  );
}

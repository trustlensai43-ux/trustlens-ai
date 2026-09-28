import React from 'react';
import { 
  ShieldCheck, 
  Home,
  Activity, 
  History, 
  BookOpen, 
  Cpu, 
  EyeOff, 
  FileText,
  Lock,
  Fingerprint
} from 'lucide-react';
import { AppRoute, ROUTE_HASHES, navigateToRoute } from '../utils/routes';
import { TrustLensLogo } from './TrustLensLogo';

interface NavbarProps {
  activeRoute: AppRoute;
  onRouteChange: (route: AppRoute) => void;
  redactPii: boolean;
  setRedactPii: (val: boolean) => void;
  historyCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeRoute,
  onRouteChange,
  redactPii,
  setRedactPii,
  historyCount,
}) => {
  const tabs = [
    { id: 'home' as const, label: 'Trang Chủ', icon: Home, hash: '#/' },
    { id: 'scan' as const, label: 'Kiểm Tra', fullSuffix: 'An Toàn', icon: Activity, hash: '#/scan' },
    { id: 'breach' as const, label: 'Lộ Dữ Liệu', icon: Fingerprint, hash: '#/breach-check' },
    { id: 'matrix' as const, label: 'Ma Trận', fullSuffix: '2 Chiều', icon: Cpu, hash: '#/matrix' },
    { id: 'scenarios' as const, label: 'Tình Huống Mẫu', icon: BookOpen, hash: '#/scenarios' },
    { id: 'history' as const, label: 'Lịch Sử', fullSuffix: 'Kiểm Tra', icon: History, hash: '#/history', count: historyCount },
    { id: 'methodology' as const, label: 'Giới Thiệu', icon: FileText, hash: '#/methodology' },
  ];

  const handleNavigate = (route: AppRoute) => {
    onRouteChange(route);
    navigateToRoute(route);
  };

  return (
    <header id="navbar" className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#080c14]/90 backdrop-blur-xl transition-colors duration-200 no-print">
      <div className="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14 gap-2">
          {/* Brand Identity */}
          <a 
            href="#/"
            onClick={(e) => {
              e.preventDefault();
              handleNavigate('home');
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            className="flex items-center gap-2.5 cursor-pointer group select-none shrink-0" 
          >
            <TrustLensLogo size="sm" />
          </a>

          {/* Desktop Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-950/80 p-1 border border-slate-800/90 rounded-xl shadow-inner shrink-0">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeRoute === tab.id;
              return (
                <a
                  key={tab.id}
                  id={`nav-tab-${tab.id}`}
                  href={tab.hash}
                  onClick={(e) => {
                    e.preventDefault();
                    handleNavigate(tab.id);
                  }}
                  className={`px-2 py-1.5 xl:px-2.5 rounded-lg flex items-center gap-1.5 whitespace-nowrap text-xs xl:text-sm font-medium transition-all duration-150 active:scale-[0.98] shrink-0 ${
                    isActive
                      ? 'bg-slate-800/95 text-white border border-slate-700 shadow-md shadow-black/40 font-semibold border-t border-t-white/15'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span className="whitespace-nowrap">
                    {tab.label}
                    {tab.fullSuffix && <span className="hidden xl:inline"> {tab.fullSuffix}</span>}
                  </span>
                  {typeof tab.count === 'number' && tab.count > 0 && (
                    <span className={`ml-0.5 px-1.5 py-0.2 rounded text-[10px] font-mono tabular-nums ${
                      isActive ? 'bg-slate-700 text-white font-bold' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {tab.count}
                    </span>
                  )}
                </a>
              );
            })}
          </nav>

          {/* Privacy Toggle & Operational Status */}
          <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
            <button
              id="toggle-pii-scrubber"
              type="button"
              onClick={() => setRedactPii(!redactPii)}
              title={redactPii ? 'Đang kích hoạt che thông tin cá nhân (CCCD, SĐT, STK, Email)' : 'Nhấp để bật ẩn thông tin cá nhân'}
              className={`text-xs px-2.5 py-1.5 rounded-xl border flex items-center gap-1.5 whitespace-nowrap transition-all duration-150 active:scale-[0.98] cursor-pointer shadow-xs ${
                redactPii 
                  ? 'bg-emerald-950/50 border-emerald-700/80 text-emerald-300 hover:bg-emerald-950/70 border-t border-t-emerald-400/20 shadow-emerald-950/20' 
                  : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-300 hover:border-slate-700'
              }`}
            >
              {redactPii ? <Lock className="w-3.5 h-3.5 text-emerald-400" /> : <EyeOff className="w-3.5 h-3.5 text-slate-500" />}
              <span className="font-medium whitespace-nowrap">Che PII:</span>
              <span className="font-mono text-[11px] font-bold">{redactPii ? 'BẬT' : 'TẮT'}</span>
            </button>

            <div className="hidden xl:flex items-center gap-1.5 text-[11px] text-slate-400 bg-slate-900/80 px-2.5 py-1.5 rounded-xl border border-slate-800/90 font-mono shadow-xs whitespace-nowrap">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Sẵn sàng</span>
            </div>
          </div>
        </div>

        {/* Mobile Navigation bar with responsive touch targets */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1.5 border-t border-slate-800/80 text-xs scrollbar-none no-scrollbar">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeRoute === tab.id;
            return (
              <a
                key={tab.id}
                href={tab.hash}
                onClick={(e) => {
                  e.preventDefault();
                  handleNavigate(tab.id);
                }}
                className={`min-h-[40px] px-3.5 py-2 rounded-xl whitespace-nowrap transition-all duration-150 active:scale-[0.98] flex items-center gap-1.5 font-medium ${
                  isActive 
                    ? 'bg-slate-800 text-white border border-slate-700 shadow-sm border-t border-t-white/15' 
                    : 'text-slate-400 hover:text-slate-200 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-300 font-bold">
                    {tab.count}
                  </span>
                )}
              </a>
            );
          })}
        </div>
      </div>
    </header>
  );
};

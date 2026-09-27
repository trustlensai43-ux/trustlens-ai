import React, { useState, useEffect } from 'react';
import { AnalysisResult, ModalityType } from './types';
import { Navbar } from './components/Navbar';
import { UnifiedWorkspace } from './components/UnifiedWorkspace';
import { AnalysisLoadingState } from './components/AnalysisLoadingState';
import { AnalysisResultView } from './components/AnalysisResultView';
import { ThreatSandbox } from './components/ThreatSandbox';
import { ScanHistoryView } from './components/ScanHistoryView';
import { MethodologyView } from './components/MethodologyView';
import { OrthogonalityMatrix } from './components/OrthogonalityMatrix';
import { DataBreachChecker } from './components/DataBreachChecker';
import { GoldenSecurityRules } from './components/GoldenSecurityRules';
import { HeroSection } from './components/HeroSection';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AppRoute, getRouteFromHash, navigateToRoute, getIdFromHash, parseHashRoute, getDataFromHash } from './utils/routes';
import { lookupCaseById, decodeReportFromShareableParam } from './utils/caseLookupService';
import { performSafeAnalysis } from './utils/analyzeClient';
import { ShieldCheck, Lock, AlertCircle, ArrowRight, Activity, ShieldAlert, BookOpen, Compass } from 'lucide-react';

export default function App() {
  const [activeRoute, setActiveRoute] = useState<AppRoute>(() => {
    try {
      return getRouteFromHash(typeof window !== 'undefined' ? window.location.hash : '');
    } catch {
      return 'home';
    }
  });
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [loadingModality, setLoadingModality] = useState<string>('text');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [redactPii, setRedactPii] = useState<boolean>(true);
  const [history, setHistory] = useState<AnalysisResult[]>([]);

  // Check and load deep-link Case ID or shared payload from URL hash
  const checkAndApplyDeepLinkId = (historyList?: AnalysisResult[]) => {
    try {
      const rawHash = (typeof window !== 'undefined' ? window.location.hash : '') || '#/';
      const parsed = parseHashRoute(rawHash);
      const dataParam = parsed.dataParam || getDataFromHash(rawHash);

      // Priority 1: Check compact shared data payload (cross-device instant display)
      if (dataParam) {
        const decodedReport = decodeReportFromShareableParam(dataParam);
        if (decodedReport) {
          setCurrentResult(decodedReport);
          saveToHistory(decodedReport);
          setActiveRoute('scan');
          return true;
        }
      }

      // Priority 2: Check ID parameter with Universal Case Registry & Reconstruction
      const idParam = parsed.idParam || getIdFromHash(rawHash);
      if (idParam) {
        const found = lookupCaseById(idParam);
        if (found) {
          setCurrentResult(found);
          saveToHistory(found);
          setActiveRoute('scan');
          return true;
        }
      }
    } catch (e) {
      console.warn('Error in checkAndApplyDeepLinkId:', e);
    }
    return false;
  };

  // Universal Case ID quick lookup handler for UnifiedWorkspace & History
  const handleLookupCaseId = (lookupId: string): boolean => {
    try {
      const cleanId = (lookupId || '').trim().toUpperCase();
      if (!cleanId) return false;

      const record = lookupCaseById(cleanId);
      if (record) {
        setCurrentResult(record);
        saveToHistory(record);
        setActiveRoute('scan');
        window.location.hash = `#/scan?id=${cleanId}`;
        return true;
      }
    } catch (e) {
      console.warn('Error in handleLookupCaseId:', e);
    }
    return false;
  };

  // Listen to hashchange events for client-side routing & deep-link IDs
  useEffect(() => {
    const handleHashChange = () => {
      try {
        const rawHash = window.location.hash || '#/';
        const parsed = parseHashRoute(rawHash);
        setActiveRoute(parsed.route);
        setErrorMessage(null);
        checkAndApplyDeepLinkId();
      } catch (err) {
        console.warn('Hash change handling notice:', err);
        setActiveRoute('home');
      }
    };

    window.addEventListener('hashchange', handleHashChange);

    // Normalize empty or root hash to '#/'
    if (!window.location.hash || window.location.hash === '#') {
      window.history.replaceState(null, '', '#/');
    }

    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [history]);

  const navigate = (route: AppRoute) => {
    try {
      setActiveRoute(route);
      navigateToRoute(route);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      console.warn('Navigation notice:', err);
    }
  };

  // Load history & preferences from local storage and resolve deep links
  useEffect(() => {
    try {
      const savedHistory = localStorage.getItem('trustlens_history');
      let loadedHistory: AnalysisResult[] = [];
      if (savedHistory) {
        const parsed = JSON.parse(savedHistory);
        if (Array.isArray(parsed)) {
          loadedHistory = parsed;
          setHistory(loadedHistory);
        }
      }
      const savedPiiPref = localStorage.getItem('trustlens_pii_pref');
      if (savedPiiPref !== null) {
        setRedactPii(savedPiiPref === 'true');
      }
      // Check deep link immediately after loading history
      checkAndApplyDeepLinkId(loadedHistory);
    } catch (e) {
      console.warn('Failed to load local storage state:', e);
    }
  }, []);

  // Save history to local storage
  const saveToHistory = (result: AnalysisResult) => {
    if (!result || !result.id) return;
    setHistory((prev) => {
      const prevArray = Array.isArray(prev) ? prev : [];
      const updated = [result, ...prevArray.filter((item) => item?.id !== result.id)].slice(0, 50);
      try {
        localStorage.setItem('trustlens_history', JSON.stringify(updated));
      } catch (e) {
        console.warn('Failed to save to local storage:', e);
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('trustlens_history');
    } catch (e) {
      console.warn('Failed to clear local storage:', e);
    }
  };

  const handleTogglePii = (val: boolean) => {
    setRedactPii(val);
    try {
      localStorage.setItem('trustlens_pii_pref', String(val));
    } catch (e) {
      console.warn('Failed to persist PII pref:', e);
    }
  };

  // Run analysis pipeline
  const handleAnalyze = async (payload: any) => {
    setIsLoading(true);
    setLoadingModality(payload?.modality || 'text');
    setErrorMessage(null);

    try {
      const resultData = await performSafeAnalysis(payload);
      if (resultData) {
        setCurrentResult(resultData);
        saveToHistory(resultData);
        navigate('scan'); // Navigate to /#/scan to display full result
      }
    } catch (err) {
      console.error('Failed to run analysis:', err);
      setErrorMessage('Đã xảy ra sự cố trong quá trình phân tích. Vui lòng thử lại.');
    } finally {
      setIsLoading(false);
    }
  };

  // Load threat sandbox sample into workspace
  const handleLoadFromSandbox = (data: {
    modality: ModalityType;
    text?: string;
    sender?: string;
    subject?: string;
    url?: string;
    transcript?: string;
    phoneNumber?: string;
  }) => {
    setCurrentResult(null);
    navigate('scan');
    handleAnalyze({
      modality: data.modality,
      text: data.text,
      sender: data.sender,
      subject: data.subject,
      url: data.url,
      transcript: data.transcript,
      phoneNumber: data.phoneNumber,
      options: { redactPii },
    });
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans selection:bg-indigo-900 selection:text-white relative">
      {/* Subtle, Sophisticated Radial Ambient Lighting Overlays (Hidden in Print) */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden -z-10 no-print">
        <div className="absolute -top-32 left-1/4 w-[750px] h-[450px] bg-indigo-500/[0.04] blur-[140px] rounded-full" />
        <div className="absolute top-1/3 right-1/4 w-[650px] h-[450px] bg-sky-500/[0.035] blur-[140px] rounded-full" />
        <div className="absolute bottom-1/4 left-1/3 w-[550px] h-[350px] bg-emerald-500/[0.025] blur-[130px] rounded-full" />
      </div>

      {/* Navigation Header with Hash Routing */}
      <Navbar
        activeRoute={activeRoute}
        onRouteChange={navigate}
        redactPii={redactPii}
        setRedactPii={handleTogglePii}
        historyCount={history.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 md:py-8 space-y-6 md:space-y-8">
        {/* Error Notification Banner */}
        {errorMessage && (
          <div className="p-4 rounded-2xl bg-rose-950/40 border border-rose-800/60 text-rose-200 text-xs flex items-start justify-between gap-3 shadow-xl backdrop-blur-xl border-t border-t-rose-400/20">
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block text-rose-200 tracking-tight">
                  Cảnh Báo Đường Ống Giám Định
                </span>
                <p className="mt-0.5 text-rose-300/90 leading-relaxed">{errorMessage}</p>
              </div>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-rose-400 hover:text-rose-200 font-mono text-[11px] underline shrink-0 transition-colors cursor-pointer"
            >
              Đóng
            </button>
          </div>
        )}

        <ErrorBoundary onReset={() => { setCurrentResult(null); setActiveRoute('scan'); }}>
          {/* 1. HOME ROUTE (/#/) */}
          {activeRoute === 'home' && (
            <div className="space-y-8 md:space-y-12">
              <HeroSection
                onStartAnalysis={() => {
                  setCurrentResult(null);
                  navigate('scan');
                }}
                onViewScenarios={() => navigate('scenarios')}
              />

              {/* Quick action bar leading directly to scan workspace */}
              <div className="max-w-4xl mx-auto p-6 rounded-2xl bg-gradient-to-r from-sky-950/40 via-indigo-950/30 to-purple-950/40 border border-indigo-500/30 shadow-2xl shadow-black/60 backdrop-blur-xl border-t border-t-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="space-y-1 text-center sm:text-left">
                  <h3 className="text-base font-semibold text-white tracking-tight flex items-center justify-center sm:justify-start gap-2">
                    <Activity className="w-4 h-4 text-sky-400" />
                    <span>Sẵn Sàng Kiểm Tra Một Tin Nhắn Hoặc Đường Link Nghi Vấn?</span>
                  </h3>
                  <p className="text-xs text-slate-300 font-normal">
                    Chuyển sang không gian làm việc chuyên biệt để dán nội dung hoặc tải ảnh màn hình kiểm tra ngay.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setCurrentResult(null);
                    navigate('scan');
                  }}
                  className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs whitespace-nowrap flex items-center gap-2 shadow-lg shadow-indigo-500/25 hover:-translate-y-0.5 hover:shadow-sky-500/20 active:translate-y-0 transition-all cursor-pointer"
                >
                  <span>Mở Trình Kiểm Tra Ngay</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* 2. SCAN & ANALYSIS WORKSPACE ROUTE (/#/scan) - Clean & Focused Workspace */}
          {activeRoute === 'scan' && (
            <div className="space-y-6 md:space-y-8">
              <ErrorBoundary onReset={() => { setCurrentResult(null); }}>
                {isLoading ? (
                  <AnalysisLoadingState modality={loadingModality} />
                ) : currentResult ? (
                  <AnalysisResultView
                    result={currentResult}
                    onReset={() => {
                      setCurrentResult(null);
                      window.location.hash = '#/scan';
                    }}
                  />
                ) : (
                  <UnifiedWorkspace
                    onAnalyze={handleAnalyze}
                    isLoading={isLoading}
                    redactPii={redactPii}
                    setRedactPii={handleTogglePii}
                    onLookupCaseId={handleLookupCaseId}
                  />
                )}
              </ErrorBoundary>
            </div>
          )}

          {/* 3. DATA BREACH CHECKER ROUTE (/#/breach-check) */}
          {activeRoute === 'breach' && (
            <div className="space-y-6 md:space-y-8">
              <DataBreachChecker />
            </div>
          )}

          {/* 4. DUAL-AXIS ORTHOGONAL MATRIX ROUTE (/#/matrix) */}
          {activeRoute === 'matrix' && (
            <div className="space-y-6 md:space-y-8 max-w-4xl mx-auto">
              <div className="border-b border-slate-800/80 pb-4">
                <h2 className="text-lg md:text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
                  <Compass className="w-5 h-5 text-indigo-400" />
                  <span>Mô Hình Ma Trận Trực Giao Độc Lập</span>
                </h2>
                <p className="text-xs sm:text-sm text-slate-400 mt-1 font-normal leading-relaxed">
                  Giải thích vì sao nội dung do AI tạo ra không đồng nghĩa với lừa đảo, và vì sao văn bản do con người viết tay vẫn có thể là bẫy thao túng tinh vi.
                </p>
              </div>

              <OrthogonalityMatrix
                scamScore={currentResult?.scamRisk?.score ?? 85}
                aiScore={currentResult?.aiProbability?.score ?? 15}
                activeTitle={currentResult?.quadrantClassification?.title || 'Góc Phần Tư 3: Lừa Đảo Do Con Người Soạn Thảo'}
                activeExplanation={currentResult?.quadrantClassification?.explanation || 'Các vụ lừa đảo qua mạng truyền thống, mạo danh ngân hàng hoặc tống tiền do tội phạm con người trực tiếp thực hiện.'}
              />

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="p-5 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-colors duration-200">
                  <span className="font-mono text-xs font-semibold text-emerald-400 block mb-1">
                    Góc 1: Con Người Lành Tính (Benign Human)
                  </span>
                  <p className="text-sm text-slate-400 leading-relaxed font-normal">
                    Email, tin nhắn và tài liệu chân thực thường ngày do con người viết với tên miền xác thực và ý đồ giao tiếp minh bạch.
                  </p>
                </div>

                <div className="p-5 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-colors duration-200">
                  <span className="font-mono text-xs font-semibold text-slate-200 block mb-1">
                    Góc 2: AI Hỗ Trợ Lành Tính (Benign AI)
                  </span>
                  <p className="text-sm text-slate-400 leading-relaxed font-normal">
                    Văn bản tóm tắt tự động, thư hỗ trợ khách hàng hoặc bài viết dịch thuật do AI hỗ trợ soạn thảo mà không chứa ý đồ lừa gạt.
                  </p>
                </div>

                <div className="p-5 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-colors duration-200">
                  <span className="font-mono text-xs font-semibold text-rose-400 block mb-1">
                    Góc 3: Lừa Đảo Do Con Người (Human Scam)
                  </span>
                  <p className="text-sm text-slate-400 leading-relaxed font-normal">
                    Các kịch bản tống tiền, mạo danh cơ quan công quyền, nhắn tin nợ cước do con người điều khiển không sử dụng công nghệ AI tạo sinh.
                  </p>
                </div>

                <div className="p-5 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-colors duration-200">
                  <span className="font-mono text-xs font-semibold text-amber-400 block mb-1">
                    Góc 4: Lừa Đảo Có AI Hỗ Trợ (AI Scam)
                  </span>
                  <p className="text-sm text-slate-400 leading-relaxed font-normal">
                    Chiến dịch phishing tự động hóa quy mô lớn, video deepfake mạo danh lãnh đạo hoặc giả giọng nói người thân gọi điện cầu cứu.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* 5. THREAT SANDBOX ROUTE (/#/scenarios) */}
          {activeRoute === 'scenarios' && (
            <div className="space-y-6 md:space-y-8">
              <ThreatSandbox onLoadIntoWorkspace={handleLoadFromSandbox} />
            </div>
          )}

          {/* 6. SCAN HISTORY ROUTE (/#/history) */}
          {activeRoute === 'history' && (
            <div className="space-y-6 md:space-y-8">
              <ScanHistoryView
                history={history}
                onSelectScan={(scan) => {
                  setCurrentResult(scan);
                  navigate('scan');
                }}
                onClearHistory={handleClearHistory}
              />
            </div>
          )}

          {/* 7. METHODOLOGY & STANDARDS ROUTE (/#/methodology) */}
          {activeRoute === 'methodology' && (
            <div className="space-y-6 md:space-y-8">
              <MethodologyView />
            </div>
          )}
        </ErrorBoundary>
      </main>

      {/* Persistent Critical Safety Advisories: Golden Security Rules */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-6 md:mt-8 no-print">
        <GoldenSecurityRules defaultExpanded={false} />
      </div>

      {/* Understated, Ultra-Refined Footer */}
      <footer id="footer" className="border-t border-slate-800/80 bg-[#080c14] mt-12 py-6 no-print transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400 stroke-[2]" />
            <span className="font-semibold text-slate-200">TrustLens AI</span>
            <span>• Nền tảng phân tích rủi ro số & sàng lọc đa phương thức</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-slate-400">
              <Lock className="w-3.5 h-3.5 text-slate-500" />
              Lưu trữ cục bộ (Local Storage). Phân tích bởi Gemini AI.
            </span>
            <span className="text-slate-500">NIST AI RMF 1.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

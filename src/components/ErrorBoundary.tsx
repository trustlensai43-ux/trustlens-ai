import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallbackMessage?: string;
  onReset?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary captured error:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    } else {
      window.location.hash = '#/scan';
    }
  };

  handleGoHome = () => {
    this.setState({ hasError: false, error: null });
    window.location.hash = '#/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="max-w-3xl mx-auto my-8 p-6 sm:p-8 rounded-2xl bg-slate-900/95 border border-slate-800 shadow-2xl backdrop-blur-xl text-center space-y-5">
          <div className="w-14 h-14 mx-auto rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-7 h-7" />
          </div>

          <div className="space-y-2">
            <h3 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              Đã xảy ra sự cố hiển thị nhỏ.
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 max-w-lg mx-auto leading-relaxed">
              {this.props.fallbackMessage ||
                'Hệ thống phòng vệ TrustLens đã ngăn chặn sự cố tràn màn hình đen. Bạn có thể khôi phục trạng thái làm việc an toàn ngay bên dưới.'}
            </p>
          </div>

          {this.state.error?.message && (
            <div className="p-3 rounded-lg bg-black/40 border border-slate-800 text-[11px] font-mono text-slate-400 text-left overflow-x-auto max-h-24">
              {this.state.error.message}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={this.handleReset}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs sm:text-sm flex items-center gap-2 shadow-lg shadow-indigo-500/25 transition-all cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Bấm để tải lại lượt quét</span>
            </button>
            <button
              type="button"
              onClick={this.handleGoHome}
              className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs sm:text-sm font-medium flex items-center gap-2 border border-slate-700 transition-all cursor-pointer"
            >
              <Home className="w-4 h-4" />
              <span>Về Trang Chủ</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

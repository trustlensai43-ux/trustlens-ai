import React, { useState } from 'react';
import { AnalysisResult } from '../types';
import { 
  History, 
  Search, 
  Trash2, 
  Download, 
  ExternalLink, 
  ShieldAlert, 
  Sparkles, 
  Clock, 
  Filter,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';

interface ScanHistoryViewProps {
  history: AnalysisResult[];
  onSelectScan: (scan: AnalysisResult) => void;
  onClearHistory: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  history,
  onSelectScan,
  onClearHistory,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterModality, setFilterModality] = useState('all');
  const [confirmClear, setConfirmClear] = useState(false);

  // Quick lookup by Case ID state
  const [caseIdQuery, setCaseIdQuery] = useState('');
  const [lookupFeedback, setLookupFeedback] = useState<string | null>(null);

  const handleCaseIdLookup = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanId = caseIdQuery.trim().toUpperCase();
    if (!cleanId) {
      setLookupFeedback('Vui lòng nhập mã hồ sơ giám định cần tra cứu.');
      return;
    }

    // Search in history prop first
    let found = history.find(item => item.id.toUpperCase() === cleanId);
    if (!found) {
      try {
        const raw = localStorage.getItem('trustlens_history');
        if (raw) {
          const parsed: AnalysisResult[] = JSON.parse(raw);
          found = parsed.find(item => item.id.toUpperCase() === cleanId);
        }
      } catch (err) {
        console.warn('History lookup error:', err);
      }
    }

    if (found) {
      setLookupFeedback(null);
      onSelectScan(found);
    } else {
      setLookupFeedback('Không tìm thấy hồ sơ mang mã này trong nhật ký giám định trên thiết bị. Vui lòng kiểm tra lại.');
    }
  };

  const filteredHistory = history.filter((item) => {
    // Search filter
    const matchesSearch =
      item.inputSummary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.rawInputSnippet && item.rawInputSnippet.toLowerCase().includes(searchQuery.toLowerCase()));

    // Severity filter
    const matchesSeverity =
      filterSeverity === 'all' || item.scamRisk.level === filterSeverity;

    // Modality filter
    const matchesModality =
      filterModality === 'all' || item.modality === filterModality;

    return matchesSearch && matchesSeverity && matchesModality;
  });

  const handleExportAll = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(history, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `TrustLens-Audit-History-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-zinc-400" />
            <h2 className="text-lg font-semibold text-zinc-100 tracking-tight">
              Nhật Ký Giám Định Cục Bộ (Audit Log)
            </h2>
          </div>
          <p className="text-xs text-zinc-400 mt-1 font-normal">
            Bản ghi giám định riêng tư phía máy khách. Dữ liệu chỉ được lưu trữ an toàn trong trình duyệt của bạn.
          </p>
        </div>

        {history.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              onClick={handleExportAll}
              className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-xs font-medium text-zinc-300 flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Xuất toàn bộ JSON</span>
            </button>

            {confirmClear ? (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => {
                    onClearHistory();
                    setConfirmClear(false);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-rose-950 border border-rose-800 text-xs font-semibold text-rose-300 hover:bg-rose-900 transition-colors"
                >
                  Xác nhận xóa sạch
                </button>
                <button
                  onClick={() => setConfirmClear(false)}
                  className="px-2 py-1.5 rounded-lg bg-zinc-900 text-xs text-zinc-400 hover:text-zinc-200"
                >
                  Hủy
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmClear(true)}
                className="px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:bg-rose-950/40 hover:border-rose-900 text-xs font-medium text-zinc-400 hover:text-rose-300 flex items-center gap-1.5 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Xóa lịch sử</span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* QUICK CASE ID LOOKUP PORTAL BAR */}
      <div className="bg-slate-900/80 backdrop-blur-xl border border-indigo-500/30 hover:border-indigo-500/50 rounded-2xl p-4 sm:p-5 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all">
        <form onSubmit={handleCaseIdLookup} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300 shrink-0">
            <Search className="w-4 h-4 text-sky-400 stroke-[2.5]" />
            <span>Tra cứu theo mã hồ sơ:</span>
          </div>

          <div className="relative flex-1">
            <input
              type="text"
              id="input-case-id-lookup-history"
              value={caseIdQuery}
              onChange={(e) => {
                setCaseIdQuery(e.target.value);
                if (lookupFeedback) setLookupFeedback(null);
              }}
              placeholder="Nhập mã hồ sơ giám định (VD: TL-182491-R0K3)..."
              className="w-full bg-slate-950/90 border border-slate-700/80 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 font-mono tracking-wide focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/50 transition-all"
            />
          </div>

          <button
            type="submit"
            id="btn-case-id-lookup-history"
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs whitespace-nowrap flex items-center justify-center gap-2 shadow-lg shadow-indigo-500/20 active:scale-[0.98] transition-all cursor-pointer"
          >
            <Search className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Tra Cứu</span>
          </button>
        </form>

        {/* Feedback message if lookup failed */}
        {lookupFeedback && (
          <div className="mt-3 p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-200 text-xs flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{lookupFeedback}</span>
            </div>
            <button
              type="button"
              onClick={() => setLookupFeedback(null)}
              className="text-rose-400 hover:text-rose-200 text-[11px] underline shrink-0 cursor-pointer"
            >
              Đóng
            </button>
          </div>
        )}
      </div>

      {/* Filter and Search Toolbar */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-zinc-400 absolute left-3 top-1/2 -tranzinc-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Tìm theo mã hồ sơ, từ khóa..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto flex-wrap">
          <div className="flex items-center gap-1.5 text-xs text-zinc-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Mức độ:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-zinc-200 rounded px-2 py-1 text-xs focus:outline-none font-mono"
            >
              <option value="all">Tất cả mức độ</option>
              <option value="critical">Nghiêm trọng</option>
              <option value="high">Mức cao</option>
              <option value="medium">Trung bình</option>
              <option value="low">Mức thấp</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-zinc-400 ml-auto md:ml-0">
            <span>Phương thức:</span>
            <select
              value={filterModality}
              onChange={(e) => setFilterModality(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-zinc-200 rounded px-2 py-1 text-xs focus:outline-none font-mono"
            >
              <option value="all">Tất cả phương thức</option>
              <option value="text">Tin nhắn SMS / Văn bản</option>
              <option value="email">Thư điện tử (Email)</option>
              <option value="phone">Số điện thoại / Cuộc gọi</option>
              <option value="url">Đường dẫn Website (URL)</option>
              <option value="image">Hình ảnh / Bằng chứng</option>
              <option value="video">Video / Giọng nói</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Items List */}
      {filteredHistory.length === 0 ? (
        <div className="p-12 text-center bg-zinc-900/40 border border-zinc-800 rounded-xl">
          <History className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-zinc-300">
            Chưa Có Bản Ghi Nào
          </h3>
          <p className="text-xs text-zinc-400 mt-1 max-w-sm mx-auto">
            {history.length === 0
              ? 'Các lượt giám định hoàn thành sẽ tự động xuất hiện tại nhật ký cục bộ này.'
              : 'Không có bản ghi nào khớp với điều kiện tìm kiếm và bộ lọc hiện tại.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredHistory.map((scan) => {
            const isCritical = scan.scamRisk.level === 'critical';
            const isHigh = scan.scamRisk.level === 'high';

            return (
              <div
                key={scan.id}
                onClick={() => onSelectScan(scan)}
                className="p-4 rounded-xl bg-zinc-900/90 hover:bg-zinc-850 border border-zinc-800 hover:border-zinc-700 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[11px] font-mono px-1.5 py-0.2 bg-zinc-950 text-zinc-400 rounded border border-zinc-800">
                      {scan.id}
                    </span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.2 bg-zinc-950 text-zinc-300 border border-zinc-800 rounded">
                      {scan.modality}
                    </span>
                    <div className="flex items-center gap-1 text-[11px] text-zinc-400 font-mono">
                      <Clock className="w-3 h-3" />
                      <span>{new Date(scan.timestamp).toLocaleTimeString('vi-VN')}</span>
                    </div>
                  </div>

                  <p className="text-xs text-zinc-200 font-medium truncate">
                    {scan.inputSummary}
                  </p>

                  {scan.rawInputSnippet && (
                    <p className="text-[11px] font-mono text-zinc-400 truncate">
                      "{scan.rawInputSnippet}"
                    </p>
                  )}
                </div>

                {/* Dual Score Badges */}
                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-zinc-400 block">Nguy cơ Lừa đảo</span>
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                        isCritical
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : isHigh
                          ? 'bg-amber-950 text-amber-300 border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      }`}
                    >
                      {scan.scamRisk.score}%
                    </span>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] font-mono text-zinc-400 block">Xác suất AI</span>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded border bg-zinc-950 text-zinc-300 border-zinc-800">
                      {scan.aiProbability.score}%
                    </span>
                  </div>

                  <ExternalLink className="w-4 h-4 text-zinc-400" />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

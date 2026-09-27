import React, { useState } from 'react';
import { 
  AnalysisResult, 
  ScamIndicator, 
  AiIndicator,
  VerificationSource,
  ProvenanceType 
} from '../types';
import { OFFICIAL_REPORTING_RESOURCES } from '../data/reportingResources';
import { ScoreGauge } from './ScoreGauge';
import { OrthogonalityMatrix } from './OrthogonalityMatrix';
import { VietnamActionGuide } from './VietnamActionGuide';
import { UrlInspectionCard } from './UrlInspectionCard';
import { GoldenSecurityRules } from './GoldenSecurityRules';
import { ThreatFiveDimensionsCard } from './ThreatFiveDimensionsCard';
import { 
  ShieldAlert, 
  Sparkles, 
  AlertTriangle, 
  CheckCircle2, 
  FileText, 
  ArrowLeft, 
  Printer, 
  Download, 
  Copy, 
  Check, 
  ExternalLink, 
  ShieldCheck, 
  Terminal,
  Filter,
  Info,
  Clock,
  Globe2,
  Lock,
  Cpu,
  PhoneCall,
  Activity,
  Layers,
  Database,
  Hash
} from 'lucide-react';

interface AnalysisResultViewProps {
  result: AnalysisResult;
  onReset: () => void;
}

export const AnalysisResultView: React.FC<AnalysisResultViewProps> = ({
  result,
  onReset,
}) => {
  const [activeTab, setActiveTab] = useState<'indicators' | 'technical' | 'telemetry' | 'methodology' | 'sources' | 'actions'>('indicators');
  const [copiedEnvelope, setCopiedEnvelope] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [copied, setCopied] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState<'VN' | 'US' | 'UK' | 'CA' | 'AU' | 'EU' | 'GLOBAL'>('VN');
  const [highlightedEvidence, setHighlightedEvidence] = useState<string | null>(null);

  const filteredScamIndicators = result.scamRisk.indicators.filter(ind => {
    if (severityFilter === 'all') return true;
    return ind.severity === severityFilter;
  });

  const reportingResourcesForCountry = OFFICIAL_REPORTING_RESOURCES.filter(
    r => r.countryCode === selectedCountry
  );

  // Helper for rendering 4-Tier Provenance Badges
  const renderProvenanceBadge = (provenance?: ProvenanceType) => {
    if (!provenance) return null;

    switch (provenance) {
      case 'DETERMINISTIC':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase bg-emerald-950/50 border border-emerald-800/70 text-emerald-400 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Tier 1: Deterministic
          </span>
        );
      case 'AI_HEURISTIC':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase bg-sky-950/50 border border-sky-800/70 text-sky-400 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
            Tier 2: AI Heuristic
          </span>
        );
      case 'EXTERNAL_SOURCE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase bg-amber-950/50 border border-amber-800/70 text-amber-400 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            Tier 3: External Feed
          </span>
        );
      case 'UNAVAILABLE':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono font-bold uppercase bg-rose-950/50 border border-rose-800/70 text-rose-400 shadow-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
            Tier 4: Telemetry Gap
          </span>
        );
    }
  };

  const handleCopySummary = () => {
    const textToCopy = `Hồ Sơ Sàng Lọc Tin Cậy Số TrustLens AI
Mã hồ sơ: ${result.id} | Thời gian: ${new Date(result.timestamp).toLocaleString('vi-VN')}
Loại phương thức: ${result.modality.toUpperCase()}
Công nghệ xử lý: ${result.engineUsed === 'gemini_multimodal' ? 'Mô hình AI đa phương thức Gemini' : 'Quy tắc Heuristic ngoại tuyến'}

[TRỤC 1] Nguy cơ Lừa đảo & Gian lận: ${result.scamRisk.score}% (${result.scamRisk.level})
- Độ tin cậy: ${result.scamRisk.confidence}%
- Thủ đoạn nhận diện: ${result.scamRisk.tactics.join(', ') || 'Không phát hiện'}
- Tóm tắt: ${result.scamRisk.summary}

[TRỤC 2] Xác suất Nội dung do AI tạo: ${result.aiProbability.score}% (${result.aiProbability.level})
- Độ tin cậy: ${result.aiProbability.confidence}%
- Phân loại: ${result.aiProbability.primaryType}
- Tóm tắt: ${result.aiProbability.summary}

Đánh giá góc phần tư: ${result.quadrantClassification.title}
Khuyến nghị an toàn: ${result.educationalTakeaway}`;

    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `TrustLens-Bao-Cao-${result.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800/80 no-print">
        <button
          id="btn-back-to-scanner"
          onClick={onReset}
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-300 hover:text-white transition-all active:scale-[0.98] cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4 stroke-[2]" />
          <span>Thực hiện lượt phân tích mới</span>
        </button>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            id="btn-copy-summary"
            onClick={handleCopySummary}
            className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 text-xs font-medium text-slate-300 hover:text-white transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer shadow-xs"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
            <span>{copied ? 'Đã sao chép hồ sơ' : 'Sao chép tóm tắt'}</span>
          </button>

          <button
            id="btn-download-json"
            onClick={handleDownloadJson}
            className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800/90 hover:border-slate-700 text-xs font-medium text-slate-300 hover:text-white transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Xuất tệp JSON</span>
          </button>

          <button
            id="btn-print-report"
            onClick={handlePrint}
            className="px-3 py-1.5 rounded-xl bg-slate-950/90 border border-slate-800/90 hover:border-slate-700 text-xs font-medium text-slate-200 hover:text-white transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer shadow-xs"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span>In / Lưu PDF hồ sơ</span>
          </button>
        </div>
      </div>

      {/* Incident Metadata Banner */}
      <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 transition-all duration-300 rounded-2xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-2xl shadow-black/60 border-t border-t-white/10">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
              Mã Hồ Sơ Phân Tích:
            </span>
            <span className="text-xs font-mono font-bold text-white bg-slate-950/90 px-2.5 py-0.5 rounded-lg border border-slate-800 tabular-nums">
              {result.id}
            </span>
            <span className="px-2.5 py-0.5 text-[10px] uppercase font-mono font-bold bg-slate-950/90 text-sky-300 border border-slate-800 rounded-lg">
              Phương thức: {result.modality.toUpperCase()}
            </span>
            <span className="px-2.5 py-0.5 text-[10px] font-mono text-slate-300 bg-slate-950/90 border border-slate-800 rounded-lg flex items-center gap-1">
              <Cpu className="w-3 h-3 text-sky-400" />
              {result.engineUsed === 'gemini_multimodal' ? 'Mô hình AI Gemini Đa phương thức' : 'Tập Quy tắc Heuristic Ngoại tuyến'}
            </span>
          </div>
          <p className="text-xs text-slate-300 font-normal mt-2 leading-relaxed">
            {result.inputSummary}
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 shrink-0 tabular-nums">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>{new Date(result.timestamp).toLocaleString('vi-VN')}</span>
        </div>
      </div>

      {/* Dual Orthogonal SVG Gauges (Scam Risk vs AI Probability) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ScoreGauge
          type="scam"
          score={result.scamRisk.score}
          level={result.scamRisk.level.toUpperCase()}
          confidence={result.scamRisk.confidence}
          evidenceCount={result.scamRisk.indicators?.length || 0}
          summary={(() => {
            const score = result.scamRisk.score;
            const raw = result.scamRisk.summary;
            if (score >= 70) {
              if (raw && (raw.startsWith('CẢNH BÁO') || raw.startsWith('NGUY CƠ')) && !raw.includes('thấp')) {
                return raw;
              }
              return 'NGUY CƠ LỪA ĐẢO CỰC KỲ NGUY HIỂM: Phát hiện thủ đoạn mạo danh cơ quan thẩm quyền kết hợp gây sức ép thời gian và đòi hỏi chuyển tiền.';
            }
            if (score >= 26) {
              if (raw && raw.startsWith('CẢNH BÁO') && !raw.includes('thấp')) {
                return raw;
              }
              return 'CẢNH BÁO RỦI RO TRUNG BÌNH: Phát hiện một số dấu hiệu đáng ngờ cần xác minh thêm trước khi thực hiện giao dịch.';
            }
            return raw && !raw.startsWith('CẢNH BÁO') && !raw.startsWith('NGUY CƠ')
              ? raw
              : 'Mức độ rủi ro lừa đảo thấp. Nội dung không có dấu hiệu thao túng hay yêu cầu tài chính bất thường.';
          })()}
        />

        <ScoreGauge
          type="ai"
          score={result.aiProbability.score}
          level={result.aiProbability.level}
          confidence={result.aiProbability.confidence}
          evidenceCount={(result.aiProbability.indicators?.length || 0) + (result.aiProbability.technicalCues?.length || 0)}
          summary={result.aiProbability.summary}
        />
      </div>

      {/* 2D Orthogonal Cartesian Map */}
      <OrthogonalityMatrix
        scamScore={result.scamRisk.score}
        aiScore={result.aiProbability.score}
        activeTitle={result.quadrantClassification.title}
        activeExplanation={result.quadrantClassification.explanation}
      />

      {/* 5-Dimensional Behavioral Threat Analysis Matrix */}
      {result.fiveDimensionalBreakdown && (
        <ThreatFiveDimensionsCard 
          breakdown={result.fiveDimensionalBreakdown} 
          scamScore={result.scamRisk.score} 
        />
      )}

      {/* Emergency Crisis Action Guide for Vietnam (Triggered when Scam Risk >= 50) */}
      <VietnamActionGuide
        scamScore={result.scamRisk.score}
        inputContent={result.rawInputSnippet || result.inputSummary}
        indicators={result.scamRisk.indicators}
      />

      {/* URL Domain Inspection & External Verification Panel */}
      {result.modality === 'url' && (
        <UrlInspectionCard result={result} />
      )}

      {/* Persistent Critical Safety Advisories: Golden Security Rules */}
      <GoldenSecurityRules defaultExpanded={result.scamRisk.score >= 40} />

      {/* Technical Deep Dive Navigation Panel */}
      <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 transition-all duration-300 rounded-2xl overflow-hidden shadow-2xl shadow-black/60 border-t border-t-white/10">
        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800/80 bg-slate-950/80 text-xs font-medium overflow-x-auto no-print">
          <button
            onClick={() => setActiveTab('indicators')}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
              activeTab === 'indicators'
                ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 stroke-[2] text-rose-400" />
            <span>Dấu Hiệu Cảnh Báo Lừa Đảo</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-slate-950 text-slate-300 border border-slate-800 font-bold">
              {result.scamRisk.indicators.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('technical')}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
              activeTab === 'technical'
                ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 stroke-[2] text-sky-400" />
            <span>Bằng Chứng Kỹ Thuật & Dấu Vết AI</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-slate-950 text-slate-300 border border-slate-800 font-bold">
              {result.aiProbability.indicators.length + result.aiProbability.technicalCues.length}
            </span>
          </button>

          {result.threatTelemetry && (
            <button
              onClick={() => setActiveTab('telemetry')}
              className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
                activeTab === 'telemetry'
                  ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5 text-indigo-400 stroke-[2]" />
              <span>Dữ Liệu Nhận Diện Thủ Đoạn (Telemetry)</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('methodology')}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
              activeTab === 'methodology'
                ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5 stroke-[2] text-emerald-400" />
            <span>Cách Thức Phân Tích & Đối Soát</span>
          </button>

          <button
            onClick={() => setActiveTab('sources')}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
              activeTab === 'sources'
                ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 stroke-[2] text-amber-400" />
            <span>Đối Soát Dữ Liệu Rò Rỉ Thực Tế</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-slate-950 text-slate-300 border border-slate-800 font-bold">
              {result.verificationSources.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('actions')}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors duration-150 cursor-pointer ${
              activeTab === 'actions'
                ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5 stroke-[2] text-emerald-400" />
            <span>Những Việc Bạn Nên Làm Ngay</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono tabular-nums bg-slate-950 text-slate-300 border border-slate-800 font-bold">
              {result.recommendedActions.length}
            </span>
          </button>
        </div>

        {/* Tab Content Panel */}
        <div className="p-5 sm:p-6">
          {/* TAB 1: Detected Scam Indicators */}
          {activeTab === 'indicators' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
                <div>
                  <h4 className="text-sm font-bold text-white">
                    Kẻ Xấu Có Thể Lợi Dụng Thông Tin Này Như Thế Nào? ({result.modality.toUpperCase()})
                  </h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Chỉ ra các dấu hiệu bất thường, bẫy tâm lý và nguy cơ mất tiền hoặc lộ dữ liệu mà bạn cần cảnh giác.
                  </p>
                </div>

                {/* Filter pills */}
                <div className="flex items-center gap-1 text-xs">
                  <Filter className="w-3.5 h-3.5 text-slate-400" />
                  {[
                    { key: 'all', label: 'Tất cả' },
                    { key: 'critical', label: 'Nghiêm trọng' },
                    { key: 'high', label: 'Cao' },
                    { key: 'medium', label: 'Trung bình' },
                    { key: 'low', label: 'Thấp' }
                  ].map((sev) => (
                    <button
                      key={sev.key}
                      onClick={() => setSeverityFilter(sev.key)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors cursor-pointer ${
                        severityFilter === sev.key
                          ? 'bg-slate-800 text-white border border-slate-700 font-bold shadow-xs'
                          : 'bg-slate-950/70 text-slate-400 hover:text-slate-200 border border-slate-800/80'
                      }`}
                    >
                      {sev.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Tactics badges */}
              {result.scamRisk.tactics.length > 0 && (
                <div className="flex flex-wrap gap-1.5 py-1">
                  <span className="text-xs font-mono text-slate-400 self-center mr-1">Thủ đoạn xác định:</span>
                  {result.scamRisk.tactics.map((tactic, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-0.5 text-xs rounded-lg bg-slate-950 text-slate-200 border border-slate-800 font-mono font-medium shadow-xs"
                    >
                      {tactic}
                    </span>
                  ))}
                </div>
              )}

              {/* Indicators List */}
              {filteredScamIndicators.length === 0 ? (
                <div className="p-8 text-center bg-slate-950/50 rounded-xl border border-slate-800/70">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                  <p className="text-xs font-semibold text-slate-200">
                    Không có dấu hiệu lừa đảo nào khớp với bộ lọc đã chọn.
                  </p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Nội dung phân tích không chứa các mẫu thao túng hoặc lừa đảo rõ rệt trong danh mục này.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredScamIndicators.map((ind: ScamIndicator) => {
                    const isCritical = ind.severity === 'critical';
                    const isHigh = ind.severity === 'high';
                    const isMedium = ind.severity === 'medium';
                    const isAnchorHighlighted = highlightedEvidence === ind.id;

                    return (
                      <div
                        key={ind.id}
                        className={`p-4 rounded-xl border transition-all ${
                          isAnchorHighlighted
                            ? 'ring-2 ring-sky-400 bg-slate-900 border-sky-500 shadow-lg'
                            : isCritical
                            ? 'bg-rose-950/25 border-rose-900/60'
                            : isHigh
                            ? 'bg-amber-950/25 border-amber-900/60'
                            : isMedium
                            ? 'bg-yellow-950/20 border-yellow-900/50'
                            : 'bg-slate-950/80 border-slate-800/80'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-2.5">
                            <AlertTriangle
                              className={`w-4 h-4 shrink-0 mt-0.5 ${
                                isCritical
                                  ? 'text-rose-400'
                                  : isHigh
                                  ? 'text-amber-400'
                                  : isMedium
                                  ? 'text-yellow-400'
                                  : 'text-slate-400'
                              }`}
                            />
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs font-semibold text-white">
                                  {ind.title}
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${
                                    isCritical
                                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                                      : isHigh
                                      ? 'bg-amber-950 text-amber-300 border-amber-800'
                                      : isMedium
                                      ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                                      : 'bg-slate-900 text-slate-400 border-slate-800'
                                  }`}
                                >
                                  {ind.severity === 'critical' ? 'Nghiêm trọng' : ind.severity === 'high' ? 'Mức cao' : ind.severity === 'medium' ? 'Trung bình' : 'Mức thấp'}
                                </span>
                                {renderProvenanceBadge(ind.provenance)}
                                <span className="text-[10px] font-mono text-slate-400">
                                  Phân loại: {ind.category}
                                </span>
                              </div>
                              <p className="text-xs text-slate-300 mt-1.5 font-normal leading-relaxed">
                                {ind.description}
                              </p>
                            </div>
                          </div>
                        </div>

                        {/* Evidence Quote Highlight */}
                        {ind.evidenceSnippet && (
                          <div 
                            onClick={() => setHighlightedEvidence(isAnchorHighlighted ? null : ind.id)}
                            className="mt-3 pt-2 border-t border-slate-800/80 pl-3 border-l-2 border-l-sky-500/70 bg-slate-950/90 p-2.5 rounded-lg text-xs font-mono text-slate-200 cursor-pointer hover:bg-slate-950 transition-colors"
                          >
                            <span className="text-[10px] text-sky-400 block uppercase font-sans font-semibold mb-0.5">
                              Đoạn Trích Bằng Chứng Trực Tiếp (Nhấp để đánh dấu):
                            </span>
                            "{ind.evidenceSnippet}"
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Impact Assessment Card */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 shadow-sm">
                <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1 font-semibold">
                  Đánh Giá Rủi Ro Tác Động Lên Nạn Nhân
                </span>
                <p className="text-xs text-slate-300 leading-relaxed font-normal">
                  {result.scamRisk.impactAssessment}
                </p>
              </div>
            </div>
          )}

          {/* TAB 2: Technical & AI Indicators */}
          {activeTab === 'technical' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-bold text-white">
                  Dấu Vết Ngôn Ngữ Học, Cấu Trúc Tổng Hợp & Bất Thường Cảm Quan
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Đánh giá độ trơn tru ngữ pháp, cấu trúc mẫu biểu tượng, dấu vết sinh ảnh/video khuếch tán và nhịp điệu phát âm.
                </p>
              </div>

              {/* Primary classification highlight */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex items-center justify-between shadow-xs">
                <div>
                  <span className="text-[10px] font-mono uppercase text-slate-400 block font-semibold">
                    Phân Loại Nguồn Gốc Tác Giả
                  </span>
                  <span className="text-sm font-bold text-white mt-0.5 block">
                    {result.aiProbability.primaryType}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-400 block">Chỉ Số Dấu Vết Cú Pháp AI</span>
                  <span className="text-xs font-mono font-bold text-sky-400">
                    {result.aiProbability.score}% ({result.aiProbability.confidence}% tin cậy)
                  </span>
                </div>
              </div>

              {/* Stylometric AI Trace Details */}
              {result.stylometricMetrics && (
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                    <span className="text-xs font-bold text-sky-300 flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                      Phân Tích Cú Pháp Ngôn Ngữ Học (Stylometric Metrics)
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      Điểm cú pháp: {result.stylometricMetrics.score}/100
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-normal">
                    {result.stylometricMetrics.explanation}
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 text-[11px] font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Nhịp điệu câu:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics.sentenceVariance === 'uniform_machine' ? 'Đồng nhất chuẩn máy' : result.stylometricMetrics.sentenceVariance === 'mixed' ? 'Hỗn hợp' : 'Tự nhiên con người'}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Mật độ từ nối:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics.transitionMarkerDensity === 'high' ? 'Rất cao (AI)' : result.stylometricMetrics.transitionMarkerDensity === 'moderate' ? 'Trung bình' : 'Thấp (Tự nhiên)'}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Nhiễu cảm xúc / tiếng lóng:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics.emotionalNoiseLevel === 'none_machine' ? 'Vắng mặt (Chuẩn hóa)' : 'Tự nhiên (Có slang/cảm xúc)'}
                      </span>
                    </div>
                  </div>

                  {result.stylometricMetrics.detectedMarkers.length > 0 && (
                    <div className="pt-2 flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] font-mono text-slate-400">Từ khóa dấu vết nhận diện:</span>
                      {result.stylometricMetrics.detectedMarkers.map((marker, mIdx) => (
                        <span key={mIdx} className="px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800 text-[10px] font-mono text-sky-200">
                          "{marker}"
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Technical Cues pills */}
              {result.aiProbability.technicalCues.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-mono text-slate-400 block font-semibold">Các Dấu Vết Kỹ Thuật Đã Nhận Diện:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {result.aiProbability.technicalCues.map((cue, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-300 flex items-center gap-2 shadow-xs"
                      >
                        <Sparkles className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                        <span>{cue}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI Indicators list */}
              {result.aiProbability.indicators.length > 0 && (
                <div className="space-y-2.5 pt-2">
                  <span className="text-xs font-mono text-slate-400 block font-semibold">Phân Tích Chi Tiết Dấu Hiệu Tổng Hợp:</span>
                  {result.aiProbability.indicators.map((ind: AiIndicator) => (
                    <div
                      key={ind.id}
                      className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 shadow-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-white">
                          {ind.title}
                        </span>
                        <div className="flex items-center gap-2 flex-wrap">
                          {renderProvenanceBadge(ind.provenance)}
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-semibold">
                            {ind.confidence}% độ tin cậy
                          </span>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400 block mt-1">
                        Dạng bất thường: {ind.anomalyType}
                      </span>
                      <p className="text-xs text-slate-300 mt-1.5 font-normal leading-relaxed">
                        {ind.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB: Threat Telemetry Synthesis (Multi-Source Intelligence) */}
          {activeTab === 'telemetry' && result.threatTelemetry && (
            <div className="space-y-6">
              <div className="bg-slate-950/90 border border-slate-800 rounded-2xl p-4 sm:p-5 shadow-xs">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-sky-400" />
                  <h4 className="text-sm font-bold text-white">
                    Khối Tổng Hợp Trí Tuệ Đe Dọa Đa Nguồn (Multi-Source Threat Telemetry)
                  </h4>
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Kiến trúc an toàn số tổng hợp các tín hiệu tiền trạm xác thực (Authoritative & Deterministic Signals) và đóng gói vào phong bì chuẩn hóa <code className="text-sky-300 font-mono text-[11px]">&lt;threat_telemetry&gt;</code> trước khi cung cấp cho mô hình Gemini phân tích đối chiếu chéo.
                </p>
              </div>

              {/* 4 Telemetry Modules Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* 1. External Breach Data */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Database className="w-4 h-4 text-emerald-400" />
                      <h5 className="text-xs font-semibold text-white">Đối Soát Rò Rỉ Tài Khoản (HIBP)</h5>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                      result.threatTelemetry.externalBreachData.status.startsWith('PWNED_')
                        ? 'bg-rose-950 text-rose-300 border-rose-800'
                        : result.threatTelemetry.externalBreachData.status === 'NO_BREACH_DETECTED'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        : 'bg-slate-900 text-slate-400 border-slate-800'
                    }`}>
                      {result.threatTelemetry.externalBreachData.status}
                    </span>
                  </div>

                  <div className="text-xs text-slate-300 space-y-1.5 font-mono text-[11px]">
                    <div className="flex justify-between border-b border-slate-900 pb-1">
                      <span className="text-slate-500">Nguồn dữ liệu:</span>
                      <span className="text-slate-200">{result.threatTelemetry.externalBreachData.source}</span>
                    </div>
                    {result.threatTelemetry.externalBreachData.sha1Prefix && (
                      <div className="flex justify-between border-b border-slate-900 pb-1">
                        <span className="text-slate-500">Tiền tố k-Anonymity:</span>
                        <span className="text-emerald-400">{result.threatTelemetry.externalBreachData.sha1Prefix}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-slate-500">Độ tin cậy:</span>
                      <span className="text-slate-200">{result.threatTelemetry.externalBreachData.confidence}%</span>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed pt-1">
                    {result.threatTelemetry.externalBreachData.summary}
                  </p>
                </div>

                {/* 2. Deterministic Technical Signatures */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-sky-400" />
                      <h5 className="text-xs font-semibold text-white">Chữ Ký Kỹ Thuật Xác Định</h5>
                    </div>
                    {renderProvenanceBadge('DETERMINISTIC')}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {result.threatTelemetry.deterministicTechnicalSignatures.summary}
                  </p>
                  <div className="text-[11px] font-mono text-slate-400">
                    <span>Số tín hiệu phát hiện: </span>
                    <span className="text-sky-300 font-bold">{result.threatTelemetry.deterministicTechnicalSignatures.findings.length}</span>
                  </div>
                </div>

                {/* 3. Pre-analysis Heuristic Risk */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-indigo-400" />
                      <h5 className="text-xs font-semibold text-white">Điểm Rủi Ro Sơ Bộ (Heuristic)</h5>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 border border-slate-800 text-indigo-300">
                      {result.threatTelemetry.preAnalysisHeuristicRisk.preliminaryScamScore}% sơ bộ
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {result.threatTelemetry.preAnalysisHeuristicRisk.rationale}
                  </p>
                </div>

                {/* 4. National Trustmark Context */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Globe2 className="w-4 h-4 text-amber-400" />
                      <h5 className="text-xs font-semibold text-white">Bối Cảnh Tín Nhiệm Việt Nam</h5>
                    </div>
                    {renderProvenanceBadge('EXTERNAL_SOURCE')}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed pt-1">
                    {result.threatTelemetry.nationalTrustmarkContext.note}
                  </p>
                </div>
              </div>

              {/* Raw XML Envelope Inspector */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-slate-400" />
                    <h5 className="text-xs font-semibold text-white">
                      Phong Bì Dữ Liệu Tiền Trạm XML (&lt;threat_telemetry&gt;)
                    </h5>
                  </div>
                  <button
                    onClick={() => {
                      if (result.threatTelemetry?.xmlEnvelope) {
                        navigator.clipboard.writeText(result.threatTelemetry.xmlEnvelope);
                        setCopiedEnvelope(true);
                        setTimeout(() => setCopiedEnvelope(false), 2000);
                      }
                    }}
                    className="px-3 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedEnvelope ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedEnvelope ? 'Đã sao chép XML' : 'Sao chép XML'}</span>
                  </button>
                </div>
                <p className="text-xs text-slate-400">
                  Dưới đây là cấu trúc phong bì dữ liệu thực tế được bơm trực tiếp vào đầu vào của mô hình Gemini AI Safety Architect để tiến hành tổng hợp trí tuệ:
                </p>
                <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 overflow-x-auto">
                  <pre className="text-[11px] font-mono text-emerald-400 leading-relaxed whitespace-pre">
                    {result.threatTelemetry.xmlEnvelope}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Methodology Breakdown (Audit Trail) */}
          {activeTab === 'methodology' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-bold text-white">
                  Phân Định Minh Bạch Nguồn Gốc Phân Tích (Audit Trail)
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Hệ thống phân định minh bạch giữa suy luận từ mô hình AI, thuật toán quy tắc heuristic cố định và trạng thái các kết nối ngoài.
                </p>
              </div>

              {result.methodologyBreakdown && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Model Reasoning */}
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                    <div className="flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-sky-400" />
                      <h5 className="text-xs font-semibold text-white">Suy Luận Bằng Mô Hình AI (Model-based Reasoning)</h5>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {result.methodologyBreakdown.modelReasoning}
                    </p>
                  </div>

                  {/* Deterministic Heuristics */}
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-emerald-400" />
                      <h5 className="text-xs font-semibold text-white">Tập Quy Tắc Cố Định (Deterministic Heuristics)</h5>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {result.methodologyBreakdown.deterministicHeuristics}
                    </p>
                  </div>

                  {/* External Registries */}
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                    <div className="flex items-center gap-2">
                      <Globe2 className="w-4 h-4 text-amber-400" />
                      <h5 className="text-xs font-semibold text-white">Cơ Sở Dữ Liệu & Danh Mục Ngoại Bộ</h5>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {result.methodologyBreakdown.externalRegistries}
                    </p>
                  </div>

                  {/* Limitations and Disclaimers */}
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                    <div className="flex items-center gap-2">
                      <Info className="w-4 h-4 text-slate-400" />
                      <h5 className="text-xs font-semibold text-white">Giới Hạn Kỹ Thuật & Cảnh Báo Khách Quan</h5>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {result.methodologyBreakdown.limitationsDisclaimer}
                    </p>
                  </div>
                </div>
              )}

              {/* Explicit Modality Rules */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-400 space-y-2 shadow-xs">
                <span className="font-semibold text-slate-200 block">Cam kết trung thực về khả năng kỹ thuật:</span>
                <ul className="list-disc list-inside space-y-1 text-[11px]">
                  <li><strong>Email SPF/DKIM/DMARC:</strong> Chỉ hiển thị kết quả xác thực khi có raw email headers hợp lệ. Nếu không có header, hệ thống hiển thị "Không khả dụng từ nội dung được cung cấp".</li>
                  <li><strong>Số điện thoại:</strong> Không thể khẳng định Caller ID spoofing chỉ từ số điện thoại hoặc văn bản mà không có dữ liệu hạ tầng viễn thông/STIR/SHAKEN.</li>
                  <li><strong>Hình ảnh / Video:</strong> Phân tích dựa trên thị giác máy tính và suy luận mẫu của mô hình AI, không khẳng định chứng thư số pháp lý tuyệt đối.</li>
                </ul>
              </div>
            </div>
          )}

          {/* TAB 4: Verification & External Sources (HONEST LABELS) */}
          {activeTab === 'sources' && (
            <div className="space-y-4">
              <div>
                <h4 className="text-sm font-bold text-white">
                  Trạng Thái Các Nguồn Dữ Liệu & Giao Thức Đối Chiếu
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Minh bạch phân biệt giữa kiểm tra cú pháp cục bộ, cơ sở dữ liệu ngoại tuyến và các dịch vụ viễn thông/danh bạ trực tuyến.
                </p>
              </div>

              <div className="space-y-3">
                {result.verificationSources.map((src: VerificationSource, idx: number) => {
                  const isMalicious = src.status === 'malicious';
                  const isSuspicious = src.status === 'suspicious';
                  const isUnavailable = src.status === 'unavailable_no_live_feed';
                  const isVerifiedFormat = src.status === 'verified_format';

                  return (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col sm:flex-row sm:items-start justify-between gap-3 shadow-xs"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold text-white">{src.name}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                            {src.category}
                          </span>
                          {renderProvenanceBadge(src.provenance)}
                        </div>
                        <p className="text-xs text-slate-300 font-normal mt-1">
                          {src.details}
                        </p>
                        {src.limitationNote && (
                          <p className="text-[11px] text-slate-400 font-mono italic mt-1">
                            Ghi chú giới hạn: {src.limitationNote}
                          </p>
                        )}
                      </div>

                      <div className="shrink-0 flex items-center gap-1.5">
                        <span
                          className={`px-2.5 py-1 rounded-lg text-[10px] font-mono uppercase font-bold border ${
                            isMalicious
                              ? 'bg-rose-950 text-rose-300 border-rose-800'
                              : isSuspicious
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : isUnavailable
                              ? 'bg-slate-900 text-slate-400 border-slate-700'
                              : isVerifiedFormat
                              ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                              : 'bg-slate-900 text-slate-300 border-slate-800'
                          }`}
                        >
                          {src.statusLabel || (isUnavailable ? 'Chưa thể xác minh' : isVerifiedFormat ? 'Định dạng hợp lệ' : src.status)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Scientific Limitations Card */}
              <div className="mt-4 p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 shadow-xs">
                <div className="flex items-center gap-2 mb-2">
                  <Info className="w-4 h-4 text-sky-400" />
                  <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                    Giới Hạn Khoa Học & Ngưỡng Không Chắc Chắn (NIST AI RMF 1.0)
                  </span>
                </div>
                <ul className="space-y-1.5">
                  {result.limitations.map((lim, idx) => (
                    <li key={idx} className="text-xs text-slate-400 flex items-start gap-2">
                      <span className="text-sky-400 font-mono">•</span>
                      <span>{lim}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {/* TAB 5: Recommended Actions & Country-Aware Reporting Portals */}
          {activeTab === 'actions' && (
            <div className="space-y-5">
              <div>
                <h4 className="text-sm font-bold text-white">
                  Quy Trình Phòng Vệ Khuyến Nghị & Cổng Báo Cáo Chính Thống
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Các bước xử lý ưu tiên theo mức độ khẩn cấp và các kênh tiếp nhận phản ánh lừa đảo chính thức theo quốc gia.
                </p>
              </div>

              {/* Prescribed actions list */}
              <div className="space-y-3">
                {result.recommendedActions.map((rec, idx) => {
                  const isImmediate = rec.priority === 'immediate';
                  const isRecommended = rec.priority === 'recommended';

                  return (
                    <div
                      key={idx}
                      className={`p-4 rounded-xl border flex items-start gap-3 shadow-xs ${
                        isImmediate
                          ? 'bg-rose-950/25 border-rose-900/60'
                          : isRecommended
                          ? 'bg-slate-950/60 border-slate-800'
                          : 'bg-slate-950/90 border-slate-800'
                      }`}
                    >
                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center text-xs font-mono font-bold shrink-0 mt-0.5 ${
                          isImmediate
                            ? 'bg-rose-950 text-rose-300 border border-rose-700'
                            : isRecommended
                            ? 'bg-slate-900 text-slate-300 border border-slate-700'
                            : 'bg-slate-900 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {idx + 1}
                      </div>

                      <div className="flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-bold text-white">
                            {rec.action}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${
                              isImmediate
                                ? 'bg-rose-950 text-rose-300 border-rose-800'
                                : isRecommended
                                ? 'bg-slate-900 text-slate-300 border-slate-700'
                                : 'bg-slate-900 text-slate-400 border-slate-800'
                            }`}
                          >
                            {isImmediate ? 'Khẩn cấp' : isRecommended ? 'Khuyến nghị' : 'Tùy chọn'}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1.5 font-normal leading-relaxed">
                          {rec.rationale}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Country-Aware Reporting Resources Selector */}
              <div className="p-5 rounded-2xl bg-slate-950/90 border border-slate-800 space-y-4 shadow-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Globe2 className="w-4 h-4 text-sky-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                      Cổng Báo Cáo Lừa Đảo & Cơ Quan Chức Năng Theo Khu Vực
                    </span>
                  </div>

                  {/* Country Selector Buttons */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {(['VN', 'US', 'UK', 'CA', 'AU', 'EU', 'GLOBAL'] as const).map((country) => (
                      <button
                        key={country}
                        onClick={() => setSelectedCountry(country)}
                        className={`px-3 py-1 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
                          selectedCountry === country
                            ? 'bg-slate-800 text-white border border-slate-700 font-bold shadow-xs'
                            : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                        }`}
                      >
                        {country === 'VN' && '🇻🇳 Việt Nam'}
                        {country === 'US' && '🇺🇸 Hoa Kỳ'}
                        {country === 'UK' && '🇬🇧 Vương Quốc Anh'}
                        {country === 'CA' && '🇨🇦 Canada'}
                        {country === 'AU' && '🇦🇺 Úc'}
                        {country === 'EU' && '🇪🇺 Liên Minh Châu Âu'}
                        {country === 'GLOBAL' && '🌐 Quốc Tế / APWG'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {reportingResourcesForCountry.map((res) => (
                    <div
                      key={res.id}
                      className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between shadow-xs"
                    >
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-xs font-bold text-white">
                            {res.portalName}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-950 border border-slate-800 shrink-0 font-semibold">
                            {res.countryCode}
                          </span>
                        </div>
                        <span className="text-[11px] font-medium text-slate-400 block">
                          {res.agencyName}
                        </span>
                        <p className="text-xs text-slate-300 font-normal leading-relaxed pt-1">
                          {res.description}
                        </p>
                      </div>

                      <div className="mt-3.5 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2 flex-wrap">
                        <div className="text-[10px] font-mono text-slate-400 truncate flex items-center gap-1.5">
                          {res.hotline && (
                            <span className="inline-flex items-center gap-1 text-amber-300 font-semibold">
                              <PhoneCall className="w-3 h-3" />
                              {res.hotline}
                            </span>
                          )}
                          <span>Phạm vi: {res.scope}</span>
                        </div>
                        <a
                          href={res.url}
                          target="_blank"
                          rel="noreferrer"
                          className="px-3 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-medium text-slate-200 flex items-center gap-1.5 shrink-0 transition-colors"
                        >
                          <span>Cổng chính thức</span>
                          <ExternalLink className="w-3 h-3 text-sky-400" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Educational Takeaway Callout */}
      <div className="p-5 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 text-xs flex items-start gap-3.5">
        <div className="w-8 h-8 rounded-xl bg-sky-950 border border-sky-800/60 text-sky-400 flex items-center justify-center shrink-0 shadow-xs">
          <FileText className="w-4 h-4 stroke-[2]" />
        </div>
        <div className="space-y-1.5">
          <span className="font-bold text-white text-sm block">
            Khuyến Nghị Từ TrustLens AI:
          </span>
          <p className="text-slate-300 font-normal leading-relaxed">
            {result.educationalTakeaway}
          </p>
          <p className="text-[11px] text-slate-400 font-normal leading-relaxed pt-2 border-t border-slate-800/80">
            TrustLens AI là hệ thống thẩm định an toàn số độc lập nhằm hỗ trợ cộng đồng nâng cao cảnh giác trước các thủ đoạn lừa đảo trên mạng. Kết quả phân tích mang tính tham khảo và hướng dẫn an toàn, không thay thế kết luận của cơ quan chức năng.
          </p>
        </div>
      </div>
    </div>
  );
};

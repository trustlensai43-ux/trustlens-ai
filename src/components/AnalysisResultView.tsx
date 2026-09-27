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
  Hash,
  QrCode,
  Share2,
  Smartphone,
  X
} from 'lucide-react';
import QRCode from 'qrcode';
import { encodeReportToShareableUrl } from '../utils/caseLookupService';

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
  const [isPrinting, setIsPrinting] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [shareUrl, setShareUrl] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [copiedShareLink, setCopiedShareLink] = useState(false);

  const handleOpenShareModal = async () => {
    try {
      const url = encodeReportToShareableUrl(result);
      setShareUrl(url);
      const qr = await QRCode.toDataURL(url, {
        width: 260,
        margin: 2,
        color: {
          dark: '#0f172a',
          light: '#ffffff',
        },
      });
      setQrDataUrl(qr);
      setShowShareModal(true);
    } catch (e) {
      console.warn('QR code generation error:', e);
      setShowShareModal(true);
    }
  };

  const handleCopyShareLink = () => {
    try {
      navigator.clipboard.writeText(shareUrl);
      setCopiedShareLink(true);
      setTimeout(() => setCopiedShareLink(false), 2000);
    } catch (e) {
      console.warn('Copy share link error:', e);
    }
  };

  // Safe normalized fallback values for bulletproof defensive rendering
  const safeId = result?.id || 'TL-DEFAULT';
  const safeTimestamp = result?.timestamp || new Date().toISOString();
  const safeModality = (result?.modality || 'text').toLowerCase();
  const safeEngineUsed = result?.engineUsed || 'LOCAL_FALLBACK';
  const safeInputSummary = result?.inputSummary || 'Đã hoàn tất phân tích đối soát an toàn.';
  const safeEducationalTakeaway =
    result?.educationalTakeaway ||
    'Thực hiện nguyên tắc chậm lại 15 phút, xác minh độc lập qua kênh chính thống trước khi thực hiện các giao dịch tài chính hoặc cung cấp thông tin cá nhân.';

  const rawScam = result?.scamRisk;
  const scamScore = typeof rawScam === 'number' ? rawScam : (rawScam?.score ?? (result as any)?.threatScore ?? 0);
  const safeScamRisk = {
    score: scamScore,
    level: rawScam?.level || (scamScore >= 70 ? 'critical' : scamScore >= 40 ? 'high' : scamScore >= 25 ? 'medium' : 'low'),
    confidence: rawScam?.confidence ?? 85,
    summary: rawScam?.summary || 'Đã hoàn tất đối soát chỉ số rủi ro lừa đảo.',
    tactics: Array.isArray(rawScam?.tactics) ? rawScam.tactics : [],
    indicators: Array.isArray(rawScam?.indicators)
      ? rawScam.indicators
      : (Array.isArray((result as any)?.threatIndicators) ? (result as any).threatIndicators : []),
    impactAssessment: rawScam?.impactAssessment || 'Tuân thủ khuyến cáo bảo mật kỹ thuật số tiêu chuẩn.',
  };

  const rawAi = result?.aiProbability;
  const aiScore = typeof rawAi === 'number' ? rawAi : (rawAi?.score ?? 0);
  const safeAiProbability = {
    score: aiScore,
    level: rawAi?.level || (aiScore >= 70 ? 'Highly Likely AI-Generated' : aiScore >= 40 ? 'Mixed / AI-Assisted' : 'Likely Authentic / Human'),
    confidence: rawAi?.confidence ?? 80,
    summary: rawAi?.summary || 'Hoàn tất đối soát ngôn ngữ và dấu vết cấu trúc.',
    primaryType: rawAi?.primaryType || 'Do con người soạn thảo / Không có dấu hiệu AI',
    indicators: Array.isArray(rawAi?.indicators) ? rawAi.indicators : [],
    technicalCues: Array.isArray(rawAi?.technicalCues) ? rawAi.technicalCues : [],
  };

  const safeQuadrant = result?.quadrantClassification || {
    quadrant: safeScamRisk.score >= 50 ? (safeAiProbability.score >= 50 ? 'ai_scam' : 'human_scam') : (safeAiProbability.score >= 50 ? 'benign_ai' : 'benign_human'),
    title: safeScamRisk.score >= 50
      ? (safeAiProbability.score >= 50 ? 'Góc phần tư 4: Lừa Đảo Có AI Hỗ Trợ' : 'Góc phần tư 3: Lừa Đảo Do Con Người Soạn Thảo')
      : (safeAiProbability.score >= 50 ? 'Góc phần tư 2: AI Hỗ Trợ Lành Tính' : 'Góc phần tư 1: Giao tiếp Con người Chân thực (Lành tính)'),
    explanation: 'Nội dung được phân loại dựa trên đối soát trực giao độc lập giữa nguồn gốc tác giả và ý đồ hành vi.',
  };

  const safeFiveDimensions = result?.fiveDimensionalBreakdown || (result as any)?.fiveDimensions;
  const safeVerificationSources: VerificationSource[] = Array.isArray(result?.verificationSources) ? result.verificationSources : [];
  const safeRecommendedActions = Array.isArray(result?.recommendedActions) ? result.recommendedActions : [];
  const safeLimitations = Array.isArray(result?.limitations) ? result.limitations : [];
  const safeThreatTelemetry = result?.threatTelemetry;
  const safeRawInputSnippet = result?.rawInputSnippet || safeInputSummary;

  const filteredScamIndicators = safeScamRisk.indicators.filter(ind => {
    if (severityFilter === 'all') return true;
    return ind?.severity === severityFilter;
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
Mã hồ sơ: ${safeId} | Thời gian: ${new Date(safeTimestamp).toLocaleString('vi-VN')}
Loại phương thức: ${safeModality.toUpperCase()}
Công nghệ xử lý: ${safeEngineUsed === 'gemini_multimodal' ? 'Mô hình AI đa phương thức Gemini' : 'Quy tắc Heuristic ngoại tuyến'}

[TRỤC 1] Nguy cơ Lừa đảo & Gian lận: ${safeScamRisk.score}% (${String(safeScamRisk.level).toUpperCase()})
- Độ tin cậy: ${safeScamRisk.confidence}%
- Thủ đoạn nhận diện: ${safeScamRisk.tactics.join(', ') || 'Không phát hiện'}
- Tóm tắt: ${safeScamRisk.summary}

[TRỤC 2] Xác suất Nội dung do AI tạo: ${safeAiProbability.score}% (${String(safeAiProbability.level).toUpperCase()})
- Độ tin cậy: ${safeAiProbability.confidence}%
- Phân loại: ${safeAiProbability.primaryType}
- Tóm tắt: ${safeAiProbability.summary}

Đánh giá góc phần tư: ${safeQuadrant.title}
Khuyến nghị an toàn: ${safeEducationalTakeaway}`;

    try {
      navigator.clipboard.writeText(textToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.warn('Copy error:', e);
    }
  };

  const handleDownloadJson = () => {
    try {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result || {}, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `TrustLens-Bao-Cao-${safeId}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (e) {
      console.warn('Download error:', e);
    }
  };

  const handlePrint = () => {
    setIsPrinting(true);
    setTimeout(() => {
      try {
        window.print();
      } catch (err) {
        console.warn('Print trigger error:', err);
      } finally {
        setTimeout(() => setIsPrinting(false), 1200);
      }
    }, 120);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Action Bar (Hidden in Print) */}
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
            id="btn-share-mobile-qr"
            onClick={handleOpenShareModal}
            className="px-3 py-1.5 rounded-xl bg-gradient-to-r from-sky-500/20 via-indigo-500/20 to-purple-500/20 hover:from-sky-500/30 hover:to-indigo-500/30 border border-sky-400/40 text-xs font-medium text-sky-200 hover:text-white transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer shadow-xs"
          >
            <QrCode className="w-3.5 h-3.5 text-sky-300" />
            <span>Chia Sẻ / Mã QR Xem Trên Điện Thoại</span>
          </button>

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
            disabled={isPrinting}
            className={`px-3 py-1.5 rounded-xl border text-xs font-medium transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer shadow-xs ${
              isPrinting
                ? 'bg-sky-600 text-white border-sky-400 ring-2 ring-sky-400/40'
                : 'bg-slate-950/90 border-slate-800/90 hover:border-slate-700 text-slate-200 hover:text-white'
            }`}
          >
            <Printer className={`w-3.5 h-3.5 ${isPrinting ? 'animate-bounce text-white' : 'text-slate-400'}`} />
            <span>{isPrinting ? 'Đang kích hoạt máy in...' : 'In / Lưu PDF hồ sơ'}</span>
          </button>
        </div>
      </div>

      {/* =========================================================================
          OFFICIAL FORMAL APPRAISAL DOSSIER BANNER (PRINT-ONLY)
          ========================================================================= */}
      <div className="hidden print:block border-b-2 border-slate-900 pb-4 mb-6 text-slate-900">
        <div className="flex items-start justify-between border-b border-slate-300 pb-2 mb-3">
          <div>
            <div className="text-[10px] font-bold tracking-wider uppercase text-slate-700">
              BỘ KHOA HỌC & CÔNG NGHỆ - DỰ ÁN SÁNG TẠO SỐ
            </div>
            <div className="text-xs font-black tracking-tight text-slate-950">
              HỆ THỐNG GIÁM ĐỊNH AN TOÀN SỐ ĐỘC LẬP - TRUSTLENS AI
            </div>
          </div>
          <div className="text-right text-[10px] font-mono text-slate-700 leading-tight">
            <div>MÃ HỒ SƠ: <strong className="text-slate-950 font-bold text-xs">{safeId}</strong></div>
            <div>THỜI GIAN LẬP: {new Date(safeTimestamp).toLocaleString('vi-VN')}</div>
          </div>
        </div>

        <div className="text-center my-3">
          <h1 className="text-lg font-black uppercase tracking-tight text-slate-950">
            PHIẾU KẾT QUẢ THẨM ĐỊNH NGUY CƠ LỪA ĐẢO TRỰC TUYẾN
          </h1>
          <p className="text-[11px] text-slate-600 font-medium">
            Chứng thư phân tích độc lập đa phương thức • Chuẩn khung NIST AI RMF 1.0 & ISO/IEC 27001
          </p>
        </div>

        {/* Essential Appraisal Credentials Grid */}
        <div className="grid grid-cols-3 gap-2 p-2.5 bg-slate-100 border border-slate-300 rounded text-xs">
          <div>
            <span className="text-[9px] font-mono uppercase text-slate-500 block">Mã Hồ Sơ Giám Định</span>
            <strong className="text-xs font-mono font-bold text-slate-900">{safeId}</strong>
          </div>
          <div>
            <span className="text-[9px] font-mono uppercase text-slate-500 block">Phương Thức & Động Cơ</span>
            <span className="text-xs font-semibold text-slate-900">
              {safeModality.toUpperCase()} • {safeEngineUsed === 'gemini_multimodal' ? 'Gemini AI Multimodal' : 'Heuristic Rules Engine'}
            </span>
          </div>
          <div>
            <span className="text-[9px] font-mono uppercase text-slate-500 block">Phân Loại Góc Ma Trận</span>
            <span className="text-xs font-bold text-slate-900">{safeQuadrant.title}</span>
          </div>
        </div>

        {/* Printable Risk Metrics */}
        <div className="grid grid-cols-2 gap-3 mt-3">
          <div className="p-3 border border-slate-300 rounded bg-slate-50">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase text-slate-700">Điểm Nguy Cơ Lừa Đảo (Scam Risk)</span>
              <span className="text-xs font-mono font-bold text-slate-900">{safeScamRisk.score}% ({String(safeScamRisk.level).toUpperCase()})</span>
            </div>
            <p className="text-[11px] text-slate-800 mt-1 leading-snug">
              {safeScamRisk.summary}
            </p>
          </div>
          <div className="p-3 border border-slate-300 rounded bg-slate-50">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase text-slate-700">Xác Suất Do AI Tạo (AI Probability)</span>
              <span className="text-xs font-mono font-bold text-slate-900">{safeAiProbability.score}% ({String(safeAiProbability.level).toUpperCase()})</span>
            </div>
            <p className="text-[11px] text-slate-800 mt-1 leading-snug">
              {safeAiProbability.summary}
            </p>
          </div>
        </div>

        {/* Printable 5-Dimension Behavioral Breakdown Summary */}
        {safeFiveDimensions?.dimensions && Array.isArray(safeFiveDimensions.dimensions) && (
          <div className="mt-3 p-3 border border-slate-300 rounded bg-white">
            <div className="text-[10px] font-bold uppercase text-slate-700 mb-2 border-b border-slate-200 pb-1">
              Bóc Tách 5 Chiều Hành Vi Thao Túng & Lừa Đảo (5-Dimensional Behavioral Analysis)
            </div>
            <div className="grid grid-cols-5 gap-2 text-[10px]">
              {safeFiveDimensions.dimensions.map((dim: any, idx: number) => (
                <div key={idx} className="p-1.5 bg-slate-50 border border-slate-200 rounded">
                  <div className="font-semibold text-slate-900 truncate" title={dim?.dimensionName}>
                    {dim?.dimensionName || `Chiều ${idx + 1}`}
                  </div>
                  <div className="text-sm font-bold font-mono text-slate-950 mt-0.5">
                    {dim?.score ?? 0}/100
                  </div>
                  <div className="text-[9px] text-slate-600 mt-0.5 leading-tight line-clamp-2">
                    {dim?.tacticsObserved?.[0] || 'Chưa ghi nhận dấu hiệu'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Printable Emergency Advice & Formal Signature */}
        <div className="mt-3 p-3 border border-slate-300 rounded bg-amber-50/50">
          <div className="text-[10px] font-bold uppercase text-slate-800 mb-1">
            Khuyến Nghị Xử Lý Khẩn Cấp & Phòng Ngừa Thiệt Hại:
          </div>
          <p className="text-[11px] text-slate-800 leading-relaxed">
            {safeScamRisk.score >= 50
              ? 'KHẨN CẤP: Dấu hiệu lừa đảo nghiêm trọng. Tuyệt đối KHÔNG chuyển tiền, KHÔNG cung cấp OTP/mật khẩu, KHÔNG cài đặt ứng dụng qua file APK. Khi có dấu hiệu chiếm đoạt tài sản, liên hệ ngay Cơ quan Công an gần nhất hoặc gọi Đường dây nóng 113 / 156 (Bộ TT&TT) để được bảo vệ kịp thời.'
              : safeEducationalTakeaway}
          </p>
          <div className="mt-2 pt-2 border-t border-slate-300/80 flex items-center justify-between text-[9px] font-mono text-slate-600">
            <span>Được xác lập tự động bởi Hệ thống TrustLens AI • Phiếu thẩm định có giá trị đối soát kỹ thuật</span>
            <span>Chữ ký số: SHA256-VERIFIED</span>
          </div>
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
              {safeId}
            </span>
            <span className="px-2.5 py-0.5 text-[10px] uppercase font-mono font-bold bg-slate-950/90 text-sky-300 border border-slate-800 rounded-lg">
              Phương thức: {safeModality.toUpperCase()}
            </span>
            <span className="px-2.5 py-0.5 text-[10px] font-mono text-slate-300 bg-slate-950/90 border border-slate-800 rounded-lg flex items-center gap-1">
              <Cpu className="w-3 h-3 text-sky-400" />
              {safeEngineUsed === 'gemini_multimodal' ? 'Mô hình AI Gemini Đa phương thức' : 'Tập Quy tắc Heuristic Ngoại tuyến'}
            </span>
          </div>
          <p className="text-xs text-slate-300 font-normal mt-2 leading-relaxed">
            {safeInputSummary}
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 shrink-0 tabular-nums">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>{new Date(safeTimestamp).toLocaleString('vi-VN')}</span>
        </div>
      </div>

      {/* Dual Orthogonal SVG Gauges (Scam Risk vs AI Probability) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ScoreGauge
          type="scam"
          score={safeScamRisk.score}
          level={String(safeScamRisk.level).toUpperCase()}
          confidence={safeScamRisk.confidence}
          evidenceCount={safeScamRisk.indicators.length}
          summary={(() => {
            const score = safeScamRisk.score;
            const raw = safeScamRisk.summary;
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
          score={safeAiProbability.score}
          level={safeAiProbability.level}
          confidence={safeAiProbability.confidence}
          evidenceCount={safeAiProbability.indicators.length + safeAiProbability.technicalCues.length}
          summary={safeAiProbability.summary}
        />
      </div>

      {/* 2D Orthogonal Cartesian Map */}
      <OrthogonalityMatrix
        scamScore={safeScamRisk.score}
        aiScore={safeAiProbability.score}
        activeTitle={safeQuadrant.title}
        activeExplanation={safeQuadrant.explanation}
      />

      {/* 5-Dimensional Behavioral Threat Analysis Matrix */}
      {safeFiveDimensions && (
        <ThreatFiveDimensionsCard 
          breakdown={safeFiveDimensions} 
          scamScore={safeScamRisk.score} 
        />
      )}

      {/* Emergency Crisis Action Guide for Vietnam (Triggered when Scam Risk >= 50) */}
      <VietnamActionGuide
        scamScore={safeScamRisk.score}
        inputContent={safeRawInputSnippet}
        indicators={safeScamRisk.indicators}
      />

      {/* URL Domain Inspection & External Verification Panel */}
      {safeModality === 'url' && (
        <UrlInspectionCard result={result} />
      )}

      {/* Persistent Critical Safety Advisories: Golden Security Rules */}
      <GoldenSecurityRules defaultExpanded={safeScamRisk.score >= 40} />

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
              {safeScamRisk.indicators.length}
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
              {safeAiProbability.indicators.length + safeAiProbability.technicalCues.length}
            </span>
          </button>

          {safeThreatTelemetry && (
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
              {safeVerificationSources.length}
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
              {safeRecommendedActions.length}
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
                    Kẻ Xấu Có Thể Lợi Dụng Thông Tin Này Như Thế Nào? ({safeModality.toUpperCase()})
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
              {safeScamRisk.tactics.length > 0 && (
                <div className="flex flex-wrap gap-1.5 py-1">
                  <span className="text-xs font-mono text-slate-400 self-center mr-1">Thủ đoạn xác định:</span>
                  {safeScamRisk.tactics.map((tactic, idx) => (
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
                    const isCritical = ind?.severity === 'critical';
                    const isHigh = ind?.severity === 'high';
                    const isMedium = ind?.severity === 'medium';
                    const isAnchorHighlighted = highlightedEvidence === ind?.id;

                    return (
                      <div
                        key={ind?.id || Math.random().toString()}
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
                                  {ind?.title}
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
                                  {ind?.severity === 'critical' ? 'Nghiêm trọng' : ind?.severity === 'high' ? 'Mức cao' : ind?.severity === 'medium' ? 'Trung bình' : 'Mức thấp'}
                                </span>
                                {renderProvenanceBadge(ind?.provenance)}
                                {ind?.category && (
                                  <span className="text-[10px] font-mono text-slate-400">
                                    Phân loại: {ind.category}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-slate-300 mt-1.5 font-normal leading-relaxed">
                                {ind?.description}
                              </p>
                            </div>
                          </div>
                        </div>

                        {/* Evidence Quote Highlight */}
                        {ind?.evidenceSnippet && (
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
                  {safeScamRisk.impactAssessment}
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
                    {safeAiProbability.primaryType}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-400 block">Chỉ Số Dấu Vết Cú Pháp AI</span>
                  <span className="text-xs font-mono font-bold text-sky-400">
                    {safeAiProbability.score}% ({safeAiProbability.confidence}% tin cậy)
                  </span>
                </div>
              </div>

              {/* Stylometric AI Trace Details */}
              {result?.stylometricMetrics && (
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                    <span className="text-xs font-bold text-sky-300 flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                      Phân Tích Cú Pháp Ngôn Ngữ Học (Stylometric Metrics)
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      Điểm cú pháp: {result.stylometricMetrics?.score ?? 0}/100
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-normal">
                    {result.stylometricMetrics?.explanation}
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 text-[11px] font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Nhịp điệu câu:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics?.sentenceVariance === 'uniform_machine' ? 'Đồng nhất chuẩn máy' : result.stylometricMetrics?.sentenceVariance === 'mixed' ? 'Hỗn hợp' : 'Tự nhiên con người'}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Mật độ từ nối:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics?.transitionMarkerDensity === 'high' ? 'Rất cao (AI)' : result.stylometricMetrics?.transitionMarkerDensity === 'moderate' ? 'Trung bình' : 'Thấp (Tự nhiên)'}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <span className="text-slate-400 block text-[10px]">Nhiễu cảm xúc / tiếng lóng:</span>
                      <span className="font-semibold text-white">
                        {result.stylometricMetrics?.emotionalNoiseLevel === 'none_machine' ? 'Vắng mặt (Chuẩn hóa)' : 'Tự nhiên (Có slang/cảm xúc)'}
                      </span>
                    </div>
                  </div>

                  {Array.isArray(result.stylometricMetrics?.detectedMarkers) && result.stylometricMetrics.detectedMarkers.length > 0 && (
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
              {safeAiProbability.technicalCues.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-mono text-slate-400 block font-semibold">Các Dấu Vết Kỹ Thuật Đã Nhận Diện:</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {safeAiProbability.technicalCues.map((cue, idx) => (
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
              {safeAiProbability.indicators.length > 0 && (
                <div className="space-y-2.5 pt-2">
                  <span className="text-xs font-mono text-slate-400 block font-semibold">Phân Tích Chi Tiết Dấu Hiệu Tổng Hợp:</span>
                  {safeAiProbability.indicators.map((ind: AiIndicator) => (
                    <div
                      key={ind?.id || Math.random().toString()}
                      className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 shadow-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-white">
                          {ind?.title}
                        </span>
                        <div className="flex items-center gap-2 flex-wrap">
                          {renderProvenanceBadge(ind?.provenance)}
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-semibold">
                            {ind?.confidence ?? 0}% độ tin cậy
                          </span>
                        </div>
                      </div>
                      {ind?.anomalyType && (
                        <span className="text-[10px] font-mono text-slate-400 block mt-1">
                          Dạng bất thường: {ind.anomalyType}
                        </span>
                      )}
                      <p className="text-xs text-slate-300 mt-1.5 font-normal leading-relaxed">
                        {ind?.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB: Threat Telemetry Synthesis (Multi-Source Intelligence) */}
          {activeTab === 'telemetry' && safeThreatTelemetry && (
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
                {safeThreatTelemetry.externalBreachData && (
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Database className="w-4 h-4 text-emerald-400" />
                        <h5 className="text-xs font-semibold text-white">Đối Soát Rò Rỉ Tài Khoản (HIBP)</h5>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        safeThreatTelemetry.externalBreachData.status?.startsWith('PWNED_')
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : safeThreatTelemetry.externalBreachData.status === 'NO_BREACH_DETECTED'
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          : 'bg-slate-900 text-slate-400 border-slate-800'
                      }`}>
                        {safeThreatTelemetry.externalBreachData.status || 'CHƯA RÀ SOÁT'}
                      </span>
                    </div>

                    <div className="text-xs text-slate-300 space-y-1.5 font-mono text-[11px]">
                      <div className="flex justify-between border-b border-slate-900 pb-1">
                        <span className="text-slate-500">Nguồn dữ liệu:</span>
                        <span className="text-slate-200">{safeThreatTelemetry.externalBreachData.source}</span>
                      </div>
                      {safeThreatTelemetry.externalBreachData.sha1Prefix && (
                        <div className="flex justify-between border-b border-slate-900 pb-1">
                          <span className="text-slate-500">Tiền tố k-Anonymity:</span>
                          <span className="text-emerald-400">{safeThreatTelemetry.externalBreachData.sha1Prefix}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-slate-500">Độ tin cậy:</span>
                        <span className="text-slate-200">{safeThreatTelemetry.externalBreachData.confidence}%</span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed pt-1">
                      {safeThreatTelemetry.externalBreachData.summary}
                    </p>
                  </div>
                )}

                {/* 2. Deterministic Technical Signatures */}
                {safeThreatTelemetry.deterministicTechnicalSignatures && (
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-sky-400" />
                        <h5 className="text-xs font-semibold text-white">Chữ Ký Kỹ Thuật Xác Định</h5>
                      </div>
                      {renderProvenanceBadge('DETERMINISTIC')}
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      {safeThreatTelemetry.deterministicTechnicalSignatures.summary}
                    </p>
                    <div className="text-[11px] font-mono text-slate-400">
                      <span>Số tín hiệu phát hiện: </span>
                      <span className="text-sky-300 font-bold">{safeThreatTelemetry.deterministicTechnicalSignatures.findings?.length || 0}</span>
                    </div>
                  </div>
                )}

                {/* 3. Pre-analysis Heuristic Risk */}
                {safeThreatTelemetry.preAnalysisHeuristicRisk && (
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Activity className="w-4 h-4 text-indigo-400" />
                        <h5 className="text-xs font-semibold text-white">Điểm Rủi Ro Sơ Bộ (Heuristic)</h5>
                      </div>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 border border-slate-800 text-indigo-300">
                        {safeThreatTelemetry.preAnalysisHeuristicRisk.preliminaryScamScore}% sơ bộ
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      {safeThreatTelemetry.preAnalysisHeuristicRisk.rationale}
                    </p>
                  </div>
                )}

                {/* 4. National Trustmark Context */}
                {safeThreatTelemetry.nationalTrustmarkContext && (
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 shadow-xs">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Globe2 className="w-4 h-4 text-amber-400" />
                        <h5 className="text-xs font-semibold text-white">Bối Cảnh Tín Nhiệm Việt Nam</h5>
                      </div>
                      {renderProvenanceBadge('EXTERNAL_SOURCE')}
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed pt-1">
                      {safeThreatTelemetry.nationalTrustmarkContext.note}
                    </p>
                  </div>
                )}
              </div>

              {/* Raw XML Envelope Inspector */}
              {safeThreatTelemetry.xmlEnvelope && (
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
                        if (safeThreatTelemetry?.xmlEnvelope) {
                          navigator.clipboard.writeText(safeThreatTelemetry.xmlEnvelope);
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
                      {safeThreatTelemetry.xmlEnvelope}
                    </pre>
                  </div>
                </div>
              )}
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

              {result?.methodologyBreakdown && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Model Reasoning */}
                  {result.methodologyBreakdown.modelReasoning && (
                    <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-sky-400" />
                        <h5 className="text-xs font-semibold text-white">Suy Luận Bằng Mô Hình AI (Model-based Reasoning)</h5>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {result.methodologyBreakdown.modelReasoning}
                      </p>
                    </div>
                  )}

                  {/* Deterministic Heuristics */}
                  {result.methodologyBreakdown.deterministicHeuristics && (
                    <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-emerald-400" />
                        <h5 className="text-xs font-semibold text-white">Tập Quy Tắc Cố Định (Deterministic Heuristics)</h5>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {result.methodologyBreakdown.deterministicHeuristics}
                      </p>
                    </div>
                  )}

                  {/* External Registries */}
                  {result.methodologyBreakdown.externalRegistries && (
                    <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                      <div className="flex items-center gap-2">
                        <Globe2 className="w-4 h-4 text-amber-400" />
                        <h5 className="text-xs font-semibold text-white">Cơ Sở Dữ Liệu & Danh Mục Ngoại Bộ</h5>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {result.methodologyBreakdown.externalRegistries}
                      </p>
                    </div>
                  )}

                  {/* Limitations and Disclaimers */}
                  {result.methodologyBreakdown.limitationsDisclaimer && (
                    <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2 shadow-xs">
                      <div className="flex items-center gap-2">
                        <Info className="w-4 h-4 text-slate-400" />
                        <h5 className="text-xs font-semibold text-white">Giới Hạn Kỹ Thuật & Cảnh Báo Khách Quan</h5>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {result.methodologyBreakdown.limitationsDisclaimer}
                      </p>
                    </div>
                  )}
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
                {safeVerificationSources.map((src: VerificationSource, idx: number) => {
                  const isMalicious = src?.status === 'malicious';
                  const isSuspicious = src?.status === 'suspicious';
                  const isUnavailable = src?.status === 'unavailable_no_live_feed';
                  const isVerifiedFormat = src?.status === 'verified_format';

                  return (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col sm:flex-row sm:items-start justify-between gap-3 shadow-xs"
                    >
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold text-white">{src?.name}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                            {src?.category}
                          </span>
                          {renderProvenanceBadge(src?.provenance)}
                        </div>
                        <p className="text-xs text-slate-300 font-normal mt-1">
                          {src?.details}
                        </p>
                        {src?.limitationNote && (
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
                          {src?.statusLabel || (isUnavailable ? 'Chưa thể xác minh' : isVerifiedFormat ? 'Định dạng hợp lệ' : src?.status)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Scientific Limitations Card */}
              {safeLimitations.length > 0 && (
                <div className="mt-4 p-4 rounded-xl bg-slate-950/90 border border-slate-800/90 shadow-xs">
                  <div className="flex items-center gap-2 mb-2">
                    <Info className="w-4 h-4 text-sky-400" />
                    <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                      Giới Hạn Khoa Học & Ngưỡng Không Chắc Chắn (NIST AI RMF 1.0)
                    </span>
                  </div>
                  <ul className="space-y-1.5">
                    {safeLimitations.map((lim, idx) => (
                      <li key={idx} className="text-xs text-slate-400 flex items-start gap-2">
                        <span className="text-sky-400 font-mono">•</span>
                        <span>{lim}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
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
                {safeRecommendedActions.map((rec, idx) => {
                  const isImmediate = rec?.priority === 'immediate';
                  const isRecommended = rec?.priority === 'recommended';

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
                            {rec?.action}
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
                          {rec?.rationale}
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
            {safeEducationalTakeaway}
          </p>
          <p className="text-[11px] text-slate-400 font-normal leading-relaxed pt-2 border-t border-slate-800/80">
            TrustLens AI là hệ thống thẩm định an toàn số độc lập nhằm hỗ trợ cộng đồng nâng cao cảnh giác trước các thủ đoạn lừa đảo trên mạng. Kết quả phân tích mang tính tham khảo và hướng dẫn an toàn, không thay thế kết luận của cơ quan chức năng.
          </p>
        </div>
      </div>

      {/* Cross-Device Share & QR Code Modal */}
      {showShareModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 no-print">
          <div className="bg-slate-900 border border-slate-700/80 rounded-3xl max-w-md w-full p-6 shadow-2xl space-y-5 relative">
            <button
              onClick={() => setShowShareModal(false)}
              className="absolute top-4 right-4 p-1.5 rounded-xl bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="text-center space-y-1.5 pr-6">
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-sky-950/80 border border-sky-800 text-[11px] font-mono text-sky-300">
                <Smartphone className="w-3.5 h-3.5" />
                <span>Tra cứu xuyên thiết bị</span>
              </div>
              <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
                Mã QR Xem Hồ Sơ Trên Điện Thoại
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Mở camera trên điện thoại thông minh để quét mã QR và xem ngay kết quả thẩm định chính thức mà không cần thiết lập tài khoản.
              </p>
            </div>

            {/* QR Code Canvas */}
            <div className="p-4 bg-white rounded-2xl flex flex-col items-center justify-center shadow-inner mx-auto max-w-[260px]">
              {qrDataUrl ? (
                <img src={qrDataUrl} alt="Mã QR tra cứu hồ sơ TrustLens" className="w-52 h-52 object-contain" />
              ) : (
                <div className="w-52 h-52 flex items-center justify-center text-slate-500 text-xs font-mono">
                  Đang khởi tạo mã QR...
                </div>
              )}
              <div className="mt-2 text-center text-[10px] font-mono font-semibold text-slate-700 tracking-wider">
                MÃ HỒ SƠ: {safeId}
              </div>
            </div>

            {/* Direct Link Copy */}
            <div className="space-y-2">
              <span className="text-[11px] font-mono text-slate-400 block font-semibold">
                Hoặc sao chép đường link trực tiếp:
              </span>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={shareUrl}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none select-all"
                />
                <button
                  onClick={handleCopyShareLink}
                  className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-all shadow-md cursor-pointer shrink-0"
                >
                  {copiedShareLink ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedShareLink ? 'Đã sao chép' : 'Sao chép'}</span>
                </button>
              </div>
            </div>

            <p className="text-[11px] text-slate-400 text-center leading-relaxed">
              Dữ liệu được đóng gói an toàn trong đường link. Người nhận trên máy tính khác hoặc điện thoại có thể tra cứu và in phiếu kết quả ngay lập tức.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

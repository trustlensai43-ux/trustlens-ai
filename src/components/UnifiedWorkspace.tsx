import React, { useState, useRef } from 'react';
import { ModalityType, SampleCase } from '../types';
import { SAMPLE_CASES } from '../data/sampleCases';
import { sanitizeClientPii } from '../utils/piiSanitizer';
import { performSafeAnalysis } from '../utils/analyzeClient';
import { 
  MessageSquare, 
  Mail, 
  PhoneCall, 
  Globe, 
  Image as ImageIcon, 
  Video, 
  UploadCloud, 
  Sparkles, 
  Trash2, 
  ArrowRight, 
  Info,
  AlertCircle,
  Eye,
  EyeOff,
  Filter,
  AlertTriangle,
  Search
} from 'lucide-react';

interface UnifiedWorkspaceProps {
  onAnalyze: (payload: any) => Promise<void>;
  isLoading: boolean;
  redactPii: boolean;
  setRedactPii: (val: boolean) => void;
  onLookupCaseId?: (caseId: string) => boolean;
}

export const UnifiedWorkspace: React.FC<UnifiedWorkspaceProps> = ({
  onAnalyze,
  isLoading,
  redactPii,
  setRedactPii,
  onLookupCaseId,
}) => {
  const [modality, setModality] = useState<ModalityType>('text');
  const [sampleFilter, setSampleFilter] = useState<'all' | 'suspicious' | 'benign_human' | 'benign_ai'>('all');
  const [showPiiPreview, setShowPiiPreview] = useState(false);

  // Case ID Quick Lookup State
  const [caseIdQuery, setCaseIdQuery] = useState('');
  const [lookupFeedback, setLookupFeedback] = useState<string | null>(null);

  // Text inputs
  const [textInput, setTextInput] = useState('');

  // Email inputs
  const [emailSender, setEmailSender] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');

  // Phone inputs
  const [phoneNumber, setPhoneNumber] = useState('');
  const [callerId, setCallerId] = useState('');
  const [phoneTranscript, setPhoneTranscript] = useState('');

  // URL inputs
  const [urlInput, setUrlInput] = useState('');

  // Image inputs
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageDataBase64, setImageDataBase64] = useState<string>('');
  const [imageCaption, setImageCaption] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Video inputs
  const [videoTranscript, setVideoTranscript] = useState('');
  const [videoFile, setVideoFile] = useState<File | null>(null);
  const [videoPreviewUrl, setVideoPreviewUrl] = useState<string>('');
  const videoInputRef = useRef<HTMLInputElement>(null);

  // Validation / Error state
  const [validationError, setValidationError] = useState<string | null>(null);
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null);

  // Filtered samples
  const filteredSamples = SAMPLE_CASES.filter(s => {
    if (sampleFilter === 'all') return true;
    return s.type === sampleFilter;
  });

  // Load a demonstration test case
  const handleLoadSample = (sample: SampleCase) => {
    setActiveSampleId(sample.id);
    setModality(sample.modality);
    setValidationError(null);

    if (sample.modality === 'text') {
      setTextInput(sample.sampleData.text || '');
    } else if (sample.modality === 'email') {
      setEmailSender(sample.sampleData.sender || '');
      setEmailSubject(sample.sampleData.subject || '');
      setEmailBody(sample.sampleData.body || '');
    } else if (sample.modality === 'phone') {
      setPhoneNumber(sample.sampleData.phoneNumber || '');
      setCallerId(sample.sampleData.callerId || '');
      setPhoneTranscript(sample.sampleData.transcript || '');
    } else if (sample.modality === 'url') {
      setUrlInput(sample.sampleData.url || '');
    } else if (sample.modality === 'image') {
      setImageCaption(sample.sampleData.text || '');
      if (sample.sampleData.imageSampleUrl) {
        setImageDataBase64(sample.sampleData.imageSampleUrl);
        setImageFile(null);
      }
    } else if (sample.modality === 'video') {
      setVideoTranscript(sample.sampleData.videoTranscript || '');
    }
  };

  // Image upload handler with base64 conversion
  const handleImageFileChange = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setValidationError('Vui lòng tải lên tệp hình ảnh hợp lệ (PNG, JPEG, WebP).');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setValidationError('Kích thước tệp ảnh vượt quá giới hạn 10MB.');
      return;
    }

    setValidationError(null);
    setImageFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        setImageDataBase64(e.target.result as string);
      }
    };
    reader.readAsDataURL(file);
  };

  // Video upload handler
  const handleVideoFileChange = (file: File) => {
    if (!file.type.startsWith('video/')) {
      setValidationError('Vui lòng tải lên tệp video hợp lệ (MP4, WebM, MOV).');
      return;
    }
    if (file.size > 25 * 1024 * 1024) {
      setValidationError('Kích thước tệp video vượt quá giới hạn 25MB.');
      return;
    }

    setValidationError(null);
    setVideoFile(file);
    const url = URL.createObjectURL(file);
    setVideoPreviewUrl(url);
  };

  // Clear inputs
  const handleClear = () => {
    setTextInput('');
    setEmailSender('');
    setEmailSubject('');
    setEmailBody('');
    setPhoneNumber('');
    setCallerId('');
    setPhoneTranscript('');
    setUrlInput('');
    setImageFile(null);
    setImageDataBase64('');
    setImageCaption('');
    setVideoFile(null);
    setVideoPreviewUrl('');
    setVideoTranscript('');
    setActiveSampleId(null);
    setValidationError(null);
  };

  // Helper for live PII redaction preview (Vietnamese format)
  const getRedactedPreviewText = () => {
    let raw = '';
    if (modality === 'text') raw = textInput;
    if (modality === 'email') raw = `Người gửi (From): ${emailSender}\nTiêu đề (Subject): ${emailSubject}\n\n${emailBody}`;
    if (modality === 'phone') raw = `Số điện thoại: ${phoneNumber} | Tên hiển thị (Caller ID): ${callerId}\n\n${phoneTranscript}`;
    if (modality === 'url') raw = urlInput;
    if (modality === 'image') raw = imageCaption;
    if (modality === 'video') raw = videoTranscript;

    if (!raw.trim()) return 'Chưa có nội dung nhập vào. Vui lòng nhập dữ liệu hoặc chọn mẫu thử để xem trước kết quả che bảo mật.';
    return sanitizeClientPii(raw, { preserveTargetPhone: modality === 'phone' });
  };

  // Submit scan handler
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    const payload: any = {
      modality,
      options: {
        redactPii,
      },
    };

    if (modality === 'text') {
      const activeText = textInput.trim();
      if (!activeText) {
        setValidationError('Vui lòng nhập hoặc dán nội dung tin nhắn cần phân tích.');
        return;
      }
      // Strictly pass active user text, never stale or overridden sample text
      payload.text = redactPii ? sanitizeClientPii(activeText) : activeText;
    } else if (modality === 'email') {
      const activeSender = emailSender.trim();
      const activeSubject = emailSubject.trim();
      const activeBody = emailBody.trim();
      if (!activeBody && !activeSubject) {
        setValidationError('Vui lòng cung cấp tiêu đề hoặc nội dung thư điện tử.');
        return;
      }
      payload.sender = redactPii ? sanitizeClientPii(activeSender) : activeSender;
      payload.subject = redactPii ? sanitizeClientPii(activeSubject) : activeSubject;
      payload.text = redactPii ? sanitizeClientPii(activeBody) : activeBody;
    } else if (modality === 'phone') {
      const activePhone = phoneNumber.trim();
      const activeCaller = callerId.trim();
      const activeTranscript = phoneTranscript.trim();
      if (!activePhone && !activeTranscript) {
        setValidationError('Vui lòng cung cấp số điện thoại hoặc bản ghi lời thoại cuộc gọi.');
        return;
      }
      payload.options.preserveTargetPhone = true;
      payload.phoneNumber = activePhone;
      payload.callerId = redactPii ? sanitizeClientPii(activeCaller) : activeCaller;
      payload.transcript = redactPii ? sanitizeClientPii(activeTranscript) : activeTranscript;
    } else if (modality === 'url') {
      const activeUrl = urlInput.trim();
      if (!activeUrl) {
        setValidationError('Vui lòng nhập địa chỉ URL trang web hoặc tên miền cần kiểm tra.');
        return;
      }
      payload.url = activeUrl;
    } else if (modality === 'image') {
      if (!imageDataBase64) {
        setValidationError('Vui lòng tải lên tệp hình ảnh hoặc chọn mẫu thử có sẵn.');
        return;
      }
      const activeCaption = imageCaption.trim();
      payload.imageDataBase64 = imageDataBase64;
      payload.imageMimeType = imageFile?.type || 'image/jpeg';
      payload.text = redactPii ? sanitizeClientPii(activeCaption) : activeCaption;
    } else if (modality === 'video') {
      const activeTranscript = videoTranscript.trim();
      if (!activeTranscript && !videoFile) {
        setValidationError('Vui lòng tải lên tệp video hoặc cung cấp bản ghi lời thoại.');
        return;
      }
      const sanitizedTranscript = redactPii ? sanitizeClientPii(activeTranscript) : activeTranscript;
      payload.videoTranscript = sanitizedTranscript;
      payload.text = sanitizedTranscript;
    }

    try {
      if (typeof onAnalyze === 'function') {
        await onAnalyze(payload);
      } else {
        await performSafeAnalysis(payload);
      }
    } catch {
      // Silently handle offline/preview mode and fallback to analyzeLocally without throwing uncaught console errors
      try {
        await performSafeAnalysis(payload);
      } catch {
        // Safe guaranteed execution
      }
    }
  };

  const handleLookupSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const query = caseIdQuery.trim();
    if (!query) {
      setLookupFeedback('Vui lòng nhập mã hồ sơ giám định cần tra cứu.');
      return;
    }

    if (onLookupCaseId) {
      const found = onLookupCaseId(query);
      if (!found) {
        setLookupFeedback('Không tìm thấy hồ sơ mang mã này trong nhật ký giám định trên thiết bị. Vui lòng kiểm tra lại.');
      } else {
        setLookupFeedback(null);
      }
    }
  };

  const modalityTabs = [
    { id: 'text' as const, label: 'SMS / Tin Nhắn', icon: MessageSquare },
    { id: 'email' as const, label: 'Thư Điện Tử', icon: Mail },
    { id: 'phone' as const, label: 'Cuộc Gọi / Thoại', icon: PhoneCall },
    { id: 'url' as const, label: 'URL / Tên Miền', icon: Globe },
    { id: 'image' as const, label: 'Hình Ảnh', icon: ImageIcon },
    { id: 'video' as const, label: 'Video / Media', icon: Video },
  ];

  return (
    <div id="workspace-input-section" className="max-w-5xl mx-auto space-y-6 md:space-y-8 scroll-mt-20">
      {/* Workspace Header */}
      <div className="text-center max-w-2xl mx-auto pt-2 space-y-2">
        <h2 className="text-xl md:text-2xl font-bold text-white tracking-tight">
          Kiểm Tra Độ An Toàn & Dấu Vết Lừa Đảo
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 font-normal leading-relaxed">
          Đánh giá minh bạch theo 2 góc nhìn độc lập: <strong className="text-rose-400 font-semibold">Nguy cơ Lừa đảo (0–100%)</strong> và <strong className="text-sky-300 font-semibold">Dấu vết do AI tạo ra (0–100%)</strong> trên tin nhắn, email, cuộc gọi, đường link web, ảnh và video.
        </p>
      </div>

      {/* QUICK CASE ID LOOKUP PORTAL BAR */}
      <div className="bg-slate-900/80 backdrop-blur-xl border border-indigo-500/30 hover:border-indigo-500/50 rounded-2xl p-4 sm:p-5 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all">
        <form onSubmit={handleLookupSubmit} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300 shrink-0">
            <Search className="w-4 h-4 text-sky-400 stroke-[2.5]" />
            <span>Tra cứu mã hồ sơ:</span>
          </div>

          <div className="relative flex-1">
            <input
              type="text"
              id="input-case-id-lookup"
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
            id="btn-case-id-lookup"
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

      {/* Demonstration Test Bank */}
      <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-4 sm:p-6 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 mb-3.5 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Sparkles className="w-4 h-4 text-sky-400" />
            <span>Tình Huống Thực Tế Thường Gặp Tại Việt Nam (Bấm để thử nhanh)</span>
          </div>

          {/* Sample filter tabs */}
          <div className="flex items-center gap-1 text-xs overflow-x-auto pb-0.5">
            <Filter className="w-3 h-3 text-slate-500 shrink-0" />
            {(['all', 'suspicious', 'benign_human', 'benign_ai'] as const).map((filterType) => (
              <button
                key={filterType}
                type="button"
                onClick={() => setSampleFilter(filterType)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono whitespace-nowrap transition-all duration-150 active:scale-[0.98] cursor-pointer ${
                  sampleFilter === filterType
                    ? 'bg-slate-800 text-white border border-slate-700 font-semibold shadow-xs border-t border-t-white/15'
                    : 'bg-slate-950/70 text-slate-400 hover:text-slate-200 border border-slate-800/80'
                }`}
              >
                {filterType === 'all' && 'Tất cả'}
                {filterType === 'suspicious' && 'Thủ đoạn lừa đảo'}
                {filterType === 'benign_human' && 'Người thật an toàn'}
                {filterType === 'benign_ai' && 'AI tích cực / Vô hại'}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {filteredSamples.map((sample) => {
            const isSelected = activeSampleId === sample.id;
            return (
              <button
                key={sample.id}
                type="button"
                onClick={() => handleLoadSample(sample)}
                className={`p-3.5 rounded-xl border text-left transition-all duration-150 active:scale-[0.98] cursor-pointer ${
                  isSelected
                    ? 'bg-slate-800/95 border-sky-500/70 ring-1 ring-sky-500/30 shadow-md shadow-sky-950/40'
                    : 'bg-slate-950/70 border-slate-800/80 hover:bg-slate-800/50 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className="text-xs font-semibold text-slate-200 truncate">
                    {sample.title}
                  </span>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-slate-400 uppercase font-semibold shrink-0">
                    {sample.modality}
                  </span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-1 leading-relaxed">
                  {sample.description}
                </p>
                <span className="text-[10px] font-mono text-slate-500 block mt-1.5">
                  {sample.badge}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Analysis Input Form */}
      <form onSubmit={handleSubmit} className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 rounded-2xl overflow-hidden shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
        {/* Modality Selector Bar */}
        <div className="grid grid-cols-3 sm:grid-cols-6 border-b border-slate-800/80 bg-slate-950/70 text-xs font-medium">
          {modalityTabs.map((tab) => {
            const TabIcon = tab.icon;
            const isActive = modality === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => { setModality(tab.id); setValidationError(null); }}
                className={`min-h-[46px] py-3 px-2 flex flex-col sm:flex-row items-center justify-center gap-2 border-b-2 transition-all duration-150 active:scale-[0.98] cursor-pointer ${
                  isActive
                    ? 'border-sky-400 text-white bg-slate-800/90 font-bold shadow-xs'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
                }`}
              >
                <TabIcon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                <span className="text-[11px] sm:text-xs tracking-tight">{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Dynamic Modality Input Fields */}
        <div className="p-5 md:p-6 space-y-4">
          {/* Validation Alert */}
          {validationError && (
            <div className="p-3.5 rounded-lg bg-rose-950/30 border border-rose-800/40 text-rose-300 text-xs flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span className="leading-relaxed">{validationError}</span>
            </div>
          )}

          {/* 1. TEXT / SMS MODALITY */}
          {modality === 'text' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-200">
                  Nội dung tin nhắn Zalo, SMS, Facebook Messenger hoặc đoạn chat đáng ngờ
                </label>
                <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                  {textInput.length} ký tự
                </span>
              </div>
              <textarea
                id="input-text-message"
                value={textInput}
                onChange={(e) => {
                  setTextInput(e.target.value);
                  if (activeSampleId) setActiveSampleId(null);
                }}
                placeholder="Dán nội dung tin nhắn Zalo/SMS, Facebook hoặc đoạn chat bạn nghi ngờ vào đây (Ví dụ: tin nhắn báo con cấp cứu chuyển tiền gấp, mạo danh VNeID, tuyển cộng tác viên Shopee/TikTok...)"
                rows={5}
                className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono leading-relaxed transition-all"
              />
            </div>
          )}

          {/* 2. EMAIL MODALITY */}
          {modality === 'email' && (
            <div className="space-y-3.5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-200 block mb-1">
                    Địa chỉ email người gửi
                  </label>
                  <input
                    id="input-email-sender"
                    type="text"
                    value={emailSender}
                    onChange={(e) => {
                      setEmailSender(e.target.value);
                      if (activeSampleId) setActiveSampleId(null);
                    }}
                    placeholder="Ví dụ: thongbao-thue@cuc-thue-portal.online hoặc support@nganhang-chamsoc.xyz"
                    className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono transition-all"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-200 block mb-1">
                    Tiêu đề email
                  </label>
                  <input
                    id="input-email-subject"
                    type="text"
                    value={emailSubject}
                    onChange={(e) => {
                      setEmailSubject(e.target.value);
                      if (activeSampleId) setActiveSampleId(null);
                    }}
                    placeholder="Ví dụ: [KHẨN] Thông báo quyết định truy thu nợ thuế hoặc Cảnh báo khóa tài khoản"
                    className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200 block mb-1">
                  Nội dung email hoặc đường link đính kèm trong thư
                </label>
                <textarea
                  id="input-email-body"
                  value={emailBody}
                  onChange={(e) => {
                    setEmailBody(e.target.value);
                    if (activeSampleId) setActiveSampleId(null);
                  }}
                  placeholder="Dán toàn bộ nội dung bức thư, lời chào, chữ ký hoặc các đường link có trong email vào đây..."
                  rows={5}
                  className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono leading-relaxed transition-all"
                />
              </div>
            </div>
          )}

          {/* 3. PHONE / AUDIO MODALITY */}
          {modality === 'phone' && (
            <div className="space-y-3.5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-200 block mb-1">
                    Số điện thoại gọi đến
                  </label>
                  <input
                    id="input-phone-number"
                    type="text"
                    value={phoneNumber}
                    onChange={(e) => {
                      setPhoneNumber(e.target.value);
                      if (activeSampleId) setActiveSampleId(null);
                    }}
                    placeholder="Ví dụ: 0984 123 456 hoặc +84 28 7777 xxxx"
                    className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono transition-all"
                  />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-200 block mb-1">
                    Tên hiển thị người gọi (Caller ID)
                  </label>
                  <input
                    id="input-caller-id"
                    type="text"
                    value={callerId}
                    onChange={(e) => {
                      setCallerId(e.target.value);
                      if (activeSampleId) setActiveSampleId(null);
                    }}
                    placeholder="Ví dụ: 'Bác sĩ cấp cứu', 'Cán bộ điều tra', hoặc số điện thoại lạ..."
                    className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200 block mb-1">
                  Nội dung cuộc trò chuyện / Lời thoại ghi âm
                </label>
                <textarea
                  id="input-phone-transcript"
                  value={phoneTranscript}
                  onChange={(e) => {
                    setPhoneTranscript(e.target.value);
                    if (activeSampleId) setActiveSampleId(null);
                  }}
                  placeholder="Gõ hoặc dán nội dung cuộc gọi thoại (Ví dụ: 'Mẹ ơi con bị tai nạn cấp cứu ở Chợ Rẫy, bác sĩ bảo chuyển gấp viện phí...', hoặc xưng danh cán bộ công an dọa bắt giữ...)"
                  rows={5}
                  className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono leading-relaxed transition-all"
                />
              </div>
            </div>
          )}

          {/* 4. URL MODALITY */}
          {modality === 'url' && (
            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-200 block mb-1">
                  Địa chỉ liên kết website (URL) cần kiểm tra
                </label>
                <input
                  id="input-target-url"
                  type="text"
                  value={urlInput}
                  onChange={(e) => {
                    setUrlInput(e.target.value);
                    if (activeSampleId) setActiveSampleId(null);
                  }}
                  placeholder="Ví dụ: https://vneid-dichvucong.gov-portal.com hoặc https://vietcombank.vn-verify-otp.online"
                  className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono transition-all"
                />
              </div>
              <p className="text-xs text-slate-400 font-normal leading-relaxed">
                Hệ thống sẽ đối soát tên miền với danh bạ các website chính thống của cơ quan nhà nước, ngân hàng và phát hiện các thủ thuật mạo danh tinh vi.
              </p>
            </div>
          )}

          {/* 5. IMAGE / PHOTO MODALITY */}
          {modality === 'image' && (
            <div className="space-y-3.5">
              <label className="text-xs font-medium text-zinc-200 block">
                Tải lên Ảnh chụp màn hình, Giấy tờ cam kết, hoặc Ảnh chân dung AI để sàng lọc
              </label>

              {/* Media Privacy Notice */}
              <div className="flex items-start gap-2.5 p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 text-amber-300 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                <div className="space-y-0.5">
                  <p className="font-semibold text-amber-200 text-xs">Lưu ý bảo vệ quyền riêng tư tệp đa phương tiện:</p>
                  <p className="text-[11px] text-amber-300/90 leading-relaxed">
                    Tệp đa phương tiện chưa hỗ trợ tự động che thông tin cá nhân (PII); vui lòng làm mờ thông tin nhạy cảm trước khi tải lên.
                  </p>
                  <p className="text-[10px] text-zinc-400 pt-0.5">
                    Mô hình đánh giá dấu hiệu thị giác chưa nhất quán; không thay thế cho phần mềm chuyên dụng kiểm tra trắc sinh học.
                  </p>
                </div>
              </div>

              {/* Drag and Drop Zone */}
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files?.[0]) {
                    handleImageFileChange(e.dataTransfer.files[0]);
                  }
                }}
                className="border border-dashed border-zinc-800/80 hover:border-zinc-600 rounded-xl p-6 text-center cursor-pointer bg-zinc-950/40 hover:bg-zinc-950/80 transition-all duration-150"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files?.[0]) handleImageFileChange(e.target.files[0]);
                  }}
                />

                {imageDataBase64 ? (
                  <div className="space-y-2">
                    <img
                      src={imageDataBase64}
                      alt="Mục tiêu phân tích"
                      referrerPolicy="no-referrer"
                      className="max-h-48 mx-auto rounded-lg border border-zinc-800 object-contain shadow-xs"
                    />
                    <p className="text-xs text-zinc-300 font-medium">
                      Đã đính kèm ảnh ({imageFile ? imageFile.name : 'Mẫu thử mô phỏng'})
                    </p>
                    <p className="text-[11px] text-zinc-500 font-mono">
                      Nhấp hoặc kéo thả để thay thế ảnh khác
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <UploadCloud className="w-8 h-8 text-zinc-400 mx-auto" />
                    <p className="text-xs font-medium text-zinc-300">
                      Kéo thả hình ảnh vào đây, hoặc <span className="text-zinc-400 underline">chọn tệp từ máy</span>
                    </p>
                    <p className="text-[11px] text-zinc-500">
                      Ảnh chụp tin nhắn, văn bản có dấu mộc, ảnh đại diện lừa đầu tư (PNG, JPG, WebP tối đa 10MB)
                    </p>
                  </div>
                )}
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200 block mb-1">
                  Văn bản chú thích hoặc ngữ cảnh bổ sung (Tùy chọn)
                </label>
                <input
                  type="text"
                  value={imageCaption}
                  onChange={(e) => {
                    setImageCaption(e.target.value);
                    if (activeSampleId) setActiveSampleId(null);
                  }}
                  placeholder="Ví dụ: Nhận được từ nhóm Telegram mời đầu tư tài chính sinh lời 25%/tuần..."
                  className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 transition-all"
                />
              </div>
            </div>
          )}

          {/* 6. VIDEO / MEDIA MODALITY */}
          {modality === 'video' && (
            <div className="space-y-3.5">
              <label className="text-xs font-semibold text-slate-200 block">
                Tải lên Đoạn Video ngắn / Sàng lọc Kịch bản Deepfake & Giọng nói Tổng hợp
              </label>

              {/* Media Privacy Notice */}
              <div className="flex items-start gap-2.5 p-3 rounded-xl bg-amber-950/20 border border-amber-800/40 text-amber-300 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                <div className="space-y-0.5">
                  <p className="font-semibold text-amber-200 text-xs">Lưu ý bảo vệ quyền riêng tư tệp đa phương tiện:</p>
                  <p className="text-[11px] text-amber-300/90 leading-relaxed">
                    Tệp đa phương tiện chưa hỗ trợ tự động che thông tin cá nhân (PII); vui lòng làm mờ thông tin nhạy cảm trước khi tải lên.
                  </p>
                  <p className="text-[10px] text-slate-400 pt-0.5">
                    Mô hình đánh giá dấu hiệu thị giác hoặc âm thanh chưa nhất quán; không thay thế cho kiểm định trắc sinh học chuyên dụng.
                  </p>
                </div>
              </div>

              <div
                onClick={() => videoInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  if (e.dataTransfer.files?.[0]) {
                    handleVideoFileChange(e.dataTransfer.files[0]);
                  }
                }}
                className="border border-dashed border-slate-800/80 hover:border-slate-600 rounded-xl p-6 text-center cursor-pointer bg-slate-950/40 hover:bg-slate-950/80 transition-all duration-150"
              >
                <input
                  ref={videoInputRef}
                  type="file"
                  accept="video/mp4,video/webm,video/quicktime"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files?.[0]) handleVideoFileChange(e.target.files[0]);
                  }}
                />

                {videoPreviewUrl ? (
                  <div className="space-y-2">
                    <video
                      src={videoPreviewUrl}
                      controls
                      className="max-h-48 mx-auto rounded-lg border border-slate-800 shadow-xs"
                    />
                    <p className="text-xs text-slate-300 font-medium">
                      Đã tải tệp video: {videoFile?.name}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      Nhấp hoặc kéo thả để thay thế video khác
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Video className="w-8 h-8 text-slate-400 mx-auto" />
                    <p className="text-xs font-medium text-slate-300">
                      Kéo thả tệp video vào đây, hoặc <span className="text-sky-400 underline">chọn tệp từ máy tính</span>
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Định dạng MP4, WebM, MOV (Tối đa 25MB). Phân tích nhịp điệu phát âm, ngữ cảnh ép buộc tài chính và dấu hiệu khuôn mặt nhân tạo.
                    </p>
                  </div>
                )}
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-200 block mb-1">
                  Bản ghi lời thoại âm thanh hoặc ngữ cảnh cuộc gọi video
                </label>
                <textarea
                  value={videoTranscript}
                  onChange={(e) => {
                    setVideoTranscript(e.target.value);
                    if (activeSampleId) setActiveSampleId(null);
                  }}
                  placeholder="Dán lời thoại video, yêu cầu tài chính khẩn cấp, hoặc nội dung chỉ thị chuyển tiền..."
                  rows={4}
                  className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500/30 font-mono leading-relaxed transition-all"
                />
              </div>
            </div>
          )}

          {/* Privacy & Safety In-situ Strip */}
          <div className="pt-3.5 border-t border-zinc-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <input
                  id="checkbox-redact-pii"
                  type="checkbox"
                  checked={redactPii}
                  onChange={(e) => setRedactPii(e.target.checked)}
                  className="rounded border-zinc-700 bg-zinc-950 text-zinc-100 focus:ring-zinc-500/30"
                />
                <label htmlFor="checkbox-redact-pii" className="text-zinc-300 cursor-pointer select-none">
                  Bảo vệ Quyền riêng tư: Tự động che CCCD, STK, OTP & Email trước khi gửi
                </label>
              </div>

              <button
                type="button"
                onClick={() => setShowPiiPreview(!showPiiPreview)}
                className="text-[11px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1 font-mono transition-colors"
              >
                {showPiiPreview ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                <span>{showPiiPreview ? 'Ẩn xem trước PII' : 'Xem trước nội dung đã che PII'}</span>
              </button>
            </div>

            <button
              type="button"
              onClick={handleClear}
              className="text-zinc-500 hover:text-zinc-300 flex items-center gap-1 text-xs transition-colors self-start sm:self-auto"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Xóa biểu mẫu</span>
            </button>
          </div>

          {/* Live PII Redaction Preview Box */}
          {showPiiPreview && (
            <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80 space-y-1.5 text-xs font-mono">
              <span className="text-[10px] text-zinc-500 uppercase font-sans font-semibold block">
                Bản xem trước dữ liệu đã che bảo mật (Dữ liệu chuyển đến động cơ phân tích):
              </span>
              <pre className="text-zinc-300 text-[11px] whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                {getRedactedPreviewText()}
              </pre>
            </div>
          )}
        </div>

        {/* Submit Bar */}
        <div className="p-4 sm:p-5 bg-slate-950/80 border-t border-slate-800/80 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="text-xs text-slate-400 hidden sm:flex items-center gap-2 font-mono">
            <Info className="w-4 h-4 text-sky-400 shrink-0" />
            <span>Chấm điểm trực giao độc lập: Nguy cơ Lừa đảo (0–100%) và Xác suất AI (0–100%).</span>
          </div>

          <button
            id="btn-run-analysis"
            type="submit"
            disabled={isLoading}
            className="w-full sm:w-auto min-h-[44px] px-7 py-3 rounded-xl bg-gradient-to-r from-sky-500 via-indigo-600 to-sky-500 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-xs sm:text-sm tracking-tight shadow-lg shadow-indigo-500/25 flex items-center justify-center gap-2.5 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-sky-500/20 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isLoading ? (
              <span>Đang đối soát & phân tích an toàn...</span>
            ) : (
              <>
                <span>Bắt Đầu Kiểm Tra Ngay</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

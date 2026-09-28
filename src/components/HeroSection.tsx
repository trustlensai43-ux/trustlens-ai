import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Sparkles, 
  ArrowDown, 
  Layers, 
  Crosshair, 
  Lock, 
  PhoneCall, 
  CheckCircle2, 
  HeartHandshake,
  MessageSquare,
  Mail,
  Phone,
  Globe,
  ImageIcon,
  Video,
  ExternalLink,
  ShieldAlert,
  Zap
} from 'lucide-react';

interface HeroSectionProps {
  onStartAnalysis: () => void;
  onViewScenarios: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onStartAnalysis,
  onViewScenarios,
}) => {
  const [activeInnovationTab, setActiveInnovationTab] = useState<'benign_ai' | 'human_scam'>('benign_ai');

  const scrollToWorkspace = () => {
    onStartAnalysis();
    const el = document.getElementById('workspace-input-section');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <section className="relative overflow-hidden pt-4 pb-12 space-y-16">
      {/* Ambient background glows for rich aesthetic depth */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[850px] h-[400px] bg-gradient-to-b from-sky-500/20 via-indigo-600/15 to-transparent blur-[120px] pointer-events-none -z-10 rounded-full" />
      <div className="absolute top-16 left-1/4 w-80 h-80 bg-cyan-500/10 blur-[90px] pointer-events-none -z-10 rounded-full" />
      <div className="absolute top-20 right-1/4 w-80 h-80 bg-indigo-500/15 blur-[90px] pointer-events-none -z-10 rounded-full" />

      {/* 1. DYNAMIC HERO HEADER */}
      <div className="text-center max-w-4xl mx-auto px-4 space-y-6">
        {/* Official Brand Emblem & Top Badge */}
        <div className="flex flex-col items-center justify-center gap-3">
          <div className="relative group">
            <div className="absolute -inset-2 rounded-2xl bg-gradient-to-r from-sky-500/30 to-cyan-500/30 blur-xl group-hover:blur-2xl transition-all duration-300" />
            <img 
              src="https://i.postimg.cc/sXwntWVn/2a-Obo-R1a-Ady-R4p-MWLfu-Cr-D8AB9LHFOPAN7JSzj-N2.jpg" 
              alt="TrustLens AI Cyber Shield & Lens Logo" 
              referrerPolicy="no-referrer"
              crossOrigin="anonymous"
              onError={(e) => {
                const target = e.currentTarget;
                if (!target.src.endsWith('/logo.png')) {
                  target.src = '/logo.png';
                }
              }}
              className="relative w-24 h-24 sm:w-28 sm:h-28 object-contain drop-shadow-[0_0_20px_rgba(56,189,248,0.6)] rounded-xl transition-transform duration-300 group-hover:scale-105"
            />
          </div>
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-slate-900/90 border border-indigo-500/30 shadow-lg shadow-indigo-950/40 backdrop-blur-xl border-t border-t-white/10">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-semibold text-slate-200 tracking-wide">
              TrustLens AI • Nền Tảng Thẩm Định An Toàn Số Độc Lập v2.0
            </span>
          </div>
        </div>

        {/* Main Headline with Modern Gradient and Ambient Radiance */}
        <h1 className="text-3xl sm:text-5xl md:text-6xl font-extrabold tracking-tight leading-[1.18] max-w-4xl mx-auto">
          <span className="text-white">Nhận Diện Thủ Đoạn </span>
          <span className="bg-gradient-to-r from-sky-400 via-cyan-300 to-blue-400 bg-clip-text text-transparent drop-shadow-[0_0_28px_rgba(56,189,248,0.35)]">
            Lừa Đảo
          </span>
          <span className="text-white"> & Nội Dung </span>
          <span className="bg-gradient-to-r from-indigo-200 via-sky-100 to-cyan-300 bg-clip-text text-transparent">
            Thao Túng Số
          </span>
        </h1>

        {/* Subtitle */}
        <p className="text-sm sm:text-base md:text-lg text-slate-300 font-normal leading-relaxed max-w-3xl mx-auto">
          Thẩm định độc lập nguy cơ lừa đảo và dấu vết trí tuệ nhân tạo trong tin nhắn, email và đường link. Giúp bạn chủ động phòng ngừa trước khi quá muộn.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3.5 pt-2">
          <button
            type="button"
            id="hero-primary-cta"
            onClick={scrollToWorkspace}
            className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-sky-500 via-indigo-600 to-sky-500 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold text-sm flex items-center gap-2.5 shadow-lg shadow-indigo-500/25 hover:-translate-y-0.5 hover:shadow-sky-500/30 active:translate-y-0 transition-all duration-200 cursor-pointer"
          >
            <span>Kiểm Tra Ngay</span>
            <ArrowDown className="w-4 h-4" />
          </button>

          <button
            type="button"
            id="hero-secondary-cta"
            onClick={onViewScenarios}
            className="px-6 py-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-800/90 text-slate-200 hover:text-white border border-slate-700/80 font-medium text-sm flex items-center gap-2.5 backdrop-blur-xl border-t border-t-white/10 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/40 active:translate-y-0 transition-all duration-200 cursor-pointer"
          >
            <Sparkles className="w-4 h-4 text-amber-400" />
            <span>Xem Tình Huống Cảnh Báo</span>
          </button>
        </div>

        {/* Reassurance tags */}
        <div className="pt-2 flex flex-wrap items-center justify-center gap-3 sm:gap-4 text-xs text-slate-300 font-medium">
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/70 border border-slate-800/80 shadow-xs">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ✓ 100% Miễn phí
          </span>
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/70 border border-slate-800/80 shadow-xs">
            <Lock className="w-3.5 h-3.5 text-sky-400" />
            ✓ Khử danh tính tại máy (Zero-Knowledge)
          </span>
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/70 border border-slate-800/80 shadow-xs">
            <HeartHandshake className="w-3.5 h-3.5 text-amber-400" />
            ✓ Tích hợp cẩm nang cứu hộ 156 & VNeID
          </span>
        </div>
      </div>

      {/* 4 KEY FEATURE PILLARS */}
      <div className="max-w-6xl mx-auto px-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Pillar 1: Sky Blue */}
        <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-sky-500/50 hover:bg-slate-900/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 group flex flex-col justify-between space-y-4 hover:-translate-y-1">
          <div>
            <div className="w-11 h-11 rounded-xl bg-sky-950/80 border border-sky-800/60 text-sky-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform duration-200 shadow-xs">
              <Layers className="w-5 h-5 stroke-[2]" />
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              6 Chế Độ Quét Đa Dạng
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed font-normal">
              Sàng lọc toàn diện từ Tin nhắn SMS, Thư điện tử, Số điện thoại/Ghi âm, Đường link website cho đến Hình ảnh & Video.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-sky-300/90 pt-3 border-t border-slate-800/80 font-medium">
            <MessageSquare className="w-3.5 h-3.5" />
            <Mail className="w-3.5 h-3.5" />
            <Phone className="w-3.5 h-3.5" />
            <Globe className="w-3.5 h-3.5" />
            <ImageIcon className="w-3.5 h-3.5" />
            <Video className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Pillar 2: Purple/Indigo */}
        <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-indigo-500/50 hover:bg-slate-900/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 group flex flex-col justify-between space-y-4 hover:-translate-y-1">
          <div>
            <div className="w-11 h-11 rounded-xl bg-indigo-950/80 border border-indigo-800/60 text-indigo-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform duration-200 shadow-xs">
              <Crosshair className="w-5 h-5 stroke-[2]" />
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Ma Trận Phân Tích 2 Chiều
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed font-normal">
              Đánh giá độc lập: Nguy cơ lừa đảo (0–100%) và Dấu vết do AI tạo ra (0–100%). Nhận biết đúng bản chất, không gắn nhãn sai lệch.
            </p>
          </div>
          <div className="text-[11px] text-indigo-300/90 pt-3 border-t border-slate-800/80 font-medium">
            Trực giao toán học • Độc lập bản quyền
          </div>
        </div>

        {/* Pillar 3: Emerald Green */}
        <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-emerald-500/50 hover:bg-slate-900/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 group flex flex-col justify-between space-y-4 hover:-translate-y-1">
          <div>
            <div className="w-11 h-11 rounded-xl bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform duration-200 shadow-xs">
              <Lock className="w-5 h-5 stroke-[2]" />
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Bảo Vệ Danh Tính k-Anonymity
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed font-normal">
              Che CCCD, SĐT, STK trực tiếp trên trình duyệt bằng thuật toán k-Anonymity và mã hóa SHA-1 trước khi phân tích.
            </p>
          </div>
          <div className="text-[11px] text-emerald-300/90 pt-3 border-t border-slate-800/80 font-medium">
            Zero-Knowledge • Dữ liệu nằm tại máy bạn
          </div>
        </div>

        {/* Pillar 4: Amber Gold */}
        <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-amber-500/50 hover:bg-slate-900/90 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 group flex flex-col justify-between space-y-4 hover:-translate-y-1">
          <div>
            <div className="w-11 h-11 rounded-xl bg-amber-950/80 border border-amber-800/60 text-amber-400 flex items-center justify-center mb-3 group-hover:scale-105 transition-transform duration-200 shadow-xs">
              <PhoneCall className="w-5 h-5 stroke-[2]" />
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Kết Nối Cứu Hộ Việt Nam
            </h3>
            <p className="text-xs text-slate-400 mt-1.5 leading-relaxed font-normal">
              Quy trình ứng cứu khẩn cấp: Hướng dẫn gọi Tổng đài 156, tố giác qua ứng dụng VNeID và tra cứu nTrust, Cổng Tín Nhiệm Mạng.
            </p>
          </div>
          <div className="text-[11px] text-amber-300/90 pt-3 border-t border-slate-800/80 font-medium">
            Phản ứng nhanh 4 bước khẩn cấp
          </div>
        </div>
      </div>

      {/* 2. STORYTELLING & PROBLEM SECTION */}
      <div className="max-w-6xl mx-auto px-4">
        <div className="p-6 sm:p-8 rounded-3xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/90 shadow-2xl shadow-black/70 border-t border-t-white/10 space-y-8">
          {/* Section Heading */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-800/80 pb-6">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-indigo-950/70 border border-indigo-800/60 text-indigo-300 text-xs font-semibold">
                <HeartHandshake className="w-3.5 h-3.5" />
                <span>Sứ Mệnh Bảo Vệ An Toàn Số</span>
              </div>
              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Sứ Mệnh Xây Dựng TrustLens AI
              </h2>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-2xl font-normal">
                Khi các chiêu trò lừa đảo mạo danh bác sĩ báo con cấp cứu, giả mạo công an khóa mã định danh VNeID hay bẫy việc làm online đang bủa vây người thân, phụ huynh và cộng đồng.
              </p>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <div className="px-4 py-2.5 rounded-xl bg-slate-950/80 border border-slate-800 text-center shadow-xs">
                <span className="text-xl font-bold font-mono text-rose-400 block tabular-nums">
                  16.000+
                </span>
                <span className="text-[10px] text-slate-400 uppercase font-medium">
                  Vụ lừa đảo mạng/năm
                </span>
              </div>
              <div className="px-4 py-2.5 rounded-xl bg-slate-950/80 border border-slate-800 text-center shadow-xs">
                <span className="text-xl font-bold font-mono text-amber-400 block tabular-nums">
                  80%
                </span>
                <span className="text-[10px] text-slate-400 uppercase font-medium">
                  Nhắm vào người yếu thế
                </span>
              </div>
            </div>
          </div>

          {/* Core Innovation Showcase: 2-Axis Contrast */}
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="text-sm sm:text-base font-semibold text-white tracking-tight flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-indigo-400" />
                  <span>Điểm Đột Phá: Phân Biệt Giữa "Công Nghệ AI" & "Ý Đồ Lừa Đảo"</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Nhiều người lầm tưởng cứ do AI làm ra là lừa đảo. Thực tế toán học hoàn toàn khác:
                </p>
              </div>

              {/* Toggle Switch */}
              <div className="flex items-center gap-1 p-1 bg-slate-950/90 rounded-xl border border-slate-800 self-start sm:self-auto text-xs">
                <button
                  type="button"
                  onClick={() => setActiveInnovationTab('benign_ai')}
                  className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                    activeInnovationTab === 'benign_ai'
                      ? 'bg-sky-950 text-sky-200 border border-sky-700/80 shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Trường hợp 1: AI Lành Tính
                </button>
                <button
                  type="button"
                  onClick={() => setActiveInnovationTab('human_scam')}
                  className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                    activeInnovationTab === 'human_scam'
                      ? 'bg-rose-950 text-rose-200 border border-rose-700/80 shadow-xs'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Trường hợp 2: Người Thật Lừa Đảo
                </button>
              </div>
            </div>

            {/* Interactive Contrast Card */}
            {activeInnovationTab === 'benign_ai' ? (
              <div className="p-5 rounded-2xl bg-gradient-to-r from-sky-950/40 via-slate-900 to-slate-900 border border-sky-800/50 space-y-3 shadow-xl">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-900/60 text-sky-300 border border-sky-700">
                      GÓC Q2: AI LÀNH TÍNH (AN TOÀN)
                    </span>
                    <span className="text-xs text-slate-300 font-medium">
                      Bài thơ chúc mừng 20/11 do ChatGPT sáng tác
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-sky-300 font-bold">Xác suất AI: 88%</span>
                    <span className="text-emerald-400 font-bold">Nguy cơ lừa đảo: 0%</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs text-slate-300 font-sans italic leading-relaxed">
                  "Bao năm bụi phấn vương đầy tóc thầy / Chở che bao chuyến đò đầy sang sông / Nhớ ơn dạy dỗ tấm lòng bao la..."
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  <strong className="text-sky-300">Nhận định của TrustLens:</strong> Dù nội dung có cấu trúc ngôn ngữ máy rõ ràng, mục đích hoàn toàn trong sáng, không chứa đường link bẫy hay đòi hỏi tiền bạc. Hệ thống phân loại chính xác là <strong>An Toàn</strong>.
                </p>
              </div>
            ) : (
              <div className="p-5 rounded-2xl bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-900 border border-rose-800/50 space-y-3 shadow-xl">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-900/60 text-rose-300 border border-rose-700">
                      GÓC Q3: NGƯỜI THẬT LỪA ĐẢO (NGUY CẤP)
                    </span>
                    <span className="text-xs text-slate-300 font-medium">
                      Tin nhắn dọa con cấp cứu đòi chuyển viện phí gấp
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="text-slate-400 font-bold">Xác suất AI: 4%</span>
                    <span className="text-rose-400 font-bold">Nguy cơ lừa đảo: 97%</span>
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-xs text-rose-200 font-sans leading-relaxed">
                  "Chị ơi cháu Minh lớp 8A bị ngã cầu thang rách đầu chảy nhiều máu, cấp cứu Chợ Rẫy. Bác sĩ yêu cầu tạm ứng viện phí 25 triệu mổ gấp. Chị chuyển gấp vào STK bệnh viện 1029384..."
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  <strong className="text-rose-300">Nhận định của TrustLens:</strong> Đây là tin nhắn do kẻ lừa đảo trực tiếp gõ tay (AI cực thấp), nhưng đánh mạnh vào tâm lý hoảng loạn của phụ huynh. TrustLens ngay lập tức phát hiện bẫy tâm lý và kích hoạt <strong>Quy trình Cứu hộ Khẩn cấp</strong>.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 3. 3 BƯỚC BẢO VỆ ĐƠN GIẢN */}
      <div className="max-w-6xl mx-auto px-4 space-y-6">
        <div className="text-center space-y-1.5">
          <span className="text-xs font-mono uppercase tracking-wider text-indigo-400 font-semibold">
            Quy Trình Hoạt Động
          </span>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            3 Bước Bảo Vệ Đơn Giản Cho Mọi Người
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto font-normal">
            Không cần kiến thức công nghệ phức tạp, bất kỳ ai cũng có thể tự kiểm tra một tin nhắn nghi vấn chỉ trong vài giây.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Step 1 */}
          <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 flex flex-col justify-between space-y-4 hover:-translate-y-1">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800/80 text-sky-400 font-mono font-bold text-sm flex items-center justify-center">
                  01
                </span>
                <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Bước Đầu Tiên
                </span>
              </div>
              <h3 className="text-base font-semibold text-white tracking-tight">
                Nhập Hoặc Dán Nội Dung Nghi Vấn
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed font-normal">
                Dán đoạn tin nhắn SMS, nội dung email, đường link website, số điện thoại lạ hoặc tải ảnh chụp màn hình/video nghi vấn vào ô kiểm tra.
              </p>
            </div>
            <div className="text-[11px] text-sky-400/90 font-medium flex items-center gap-1 pt-3 border-t border-slate-800/60">
              <span>Hỗ trợ 6 định dạng phổ biến</span>
            </div>
          </div>

          {/* Step 2 */}
          <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 flex flex-col justify-between space-y-4 hover:-translate-y-1">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-800/80 text-indigo-400 font-mono font-bold text-sm flex items-center justify-center">
                  02
                </span>
                <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Bảo Vệ Riêng Tư
                </span>
              </div>
              <h3 className="text-base font-semibold text-white tracking-tight">
                Che Thông Tin Cá Nhân Cục Bộ
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed font-normal">
                Thuật toán tự động tìm và che kín số CCCD, tài khoản ngân hàng và số điện thoại ngay trên máy bạn. Sau đó phân tích bẫy tâm lý và dấu vết AI.
              </p>
            </div>
            <div className="text-[11px] text-indigo-400/90 font-medium flex items-center gap-1 pt-3 border-t border-slate-800/60">
              <span>Chuẩn an toàn Zero-Knowledge</span>
            </div>
          </div>

          {/* Step 3 */}
          <div className="p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300 flex flex-col justify-between space-y-4 hover:-translate-y-1">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-800/80 text-emerald-400 font-mono font-bold text-sm flex items-center justify-center">
                  03
                </span>
                <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">
                  Hành Động An Toàn
                </span>
              </div>
              <h3 className="text-base font-semibold text-white tracking-tight">
                Xem Điểm Rủi Ro & Cách Xử Lý
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed font-normal">
                Xem ngay tọa độ nguy cơ trên bản đồ 2D, các dấu hiệu bẫy tâm lý được làm nổi bật và nhận hướng dẫn gọi tổng đài 156 hoặc khóa thẻ kịp thời.
              </p>
            </div>
            <div className="text-[11px] text-emerald-400/90 font-medium flex items-center gap-1 pt-3 border-t border-slate-800/60">
              <span>Hướng dẫn chuẩn cơ quan chức năng</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

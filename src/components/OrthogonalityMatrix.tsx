import React from 'react';
import { Crosshair, UserCheck, Bot, UserX, Cpu, Info, Sparkles } from 'lucide-react';

interface OrthogonalityMatrixProps {
  scamScore: number;
  aiScore: number;
  activeTitle?: string;
  activeExplanation?: string;
}

export const OrthogonalityMatrix: React.FC<OrthogonalityMatrixProps> = ({
  scamScore,
  aiScore,
  activeTitle,
  activeExplanation,
}) => {
  // Determine current active quadrant
  const isHighScam = scamScore >= 50;
  const isHighAi = aiScore >= 50;

  // Active quadrant key
  const activeQuadKey = isHighScam
    ? (isHighAi ? 'q4' : 'q3')
    : (isHighAi ? 'q2' : 'q1');

  // Dynamic pin color based on threat level
  const pinGlowColor = isHighScam ? 'bg-rose-400' : 'bg-sky-400';
  const pinDotColor = isHighScam ? 'bg-rose-600' : 'bg-sky-600';

  return (
    <div className="relative overflow-hidden bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-5 sm:p-6 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
      {/* Subtle background ambient flare */}
      <div className="absolute top-0 right-1/4 w-72 h-72 bg-indigo-500/5 blur-3xl pointer-events-none -z-10 rounded-full" />

      {/* Header section */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-indigo-950/60 border border-indigo-800/60 flex items-center justify-center text-indigo-400">
              <Crosshair className="w-4 h-4 stroke-[2]" />
            </div>
            <h3 className="text-sm sm:text-base font-semibold text-white tracking-tight">
              Bản Đồ Phân Tích 2 Chiều: Nguy Cơ Lừa Đảo & Nguồn Gốc AI
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed font-normal">
            Phân tách độc lập giữa bản chất công nghệ (AI hay người thật) và ý đồ hành vi (Lành tính hay Lừa đảo). AI không đồng nghĩa với lừa đảo!
          </p>
        </div>
        <div className="px-3 py-1.5 bg-slate-950/90 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 tabular-nums shrink-0 shadow-xs flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
          <span>Tọa độ rủi ro: ({aiScore}% AI, {scamScore}% Lừa đảo)</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* 2D Plane Visualizer with Precision Grid */}
        <div className="lg:col-span-7 relative aspect-square max-w-[340px] mx-auto w-full bg-slate-950/90 border border-slate-800/90 rounded-2xl p-4 flex flex-col justify-between shadow-inner">
          {/* Y Axis Label */}
          <div className="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] uppercase font-mono tracking-widest text-slate-400 flex items-center gap-1 font-semibold">
            <span>▲ Nguy cơ Lừa đảo (0–100%)</span>
          </div>

          {/* X Axis Label */}
          <div className="absolute left-1/2 -translate-x-1/2 -bottom-6 text-[10px] uppercase font-mono tracking-widest text-slate-400 flex items-center gap-1 font-semibold">
            <span>Xác suất Nội dung AI (0–100%) ►</span>
          </div>

          {/* Precision Grid Lines & Quadrant Panels */}
          <div className="absolute inset-0 grid grid-cols-2 grid-rows-2 rounded-2xl overflow-hidden pointer-events-none">
            {/* Quadrant 3: High Scam / Low AI */}
            <div className={`border-r border-b border-slate-800/80 p-3 transition-colors duration-300 flex flex-col justify-between ${
              activeQuadKey === 'q3' ? 'bg-rose-950/40 shadow-inner' : 'hover:bg-slate-900/30'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-rose-300 font-bold">Q3: Người Thật Lừa Đảo</span>
                <span className="w-2 h-2 rounded-full bg-rose-500/80" />
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">Lừa đảo cực cao • Gõ tay thủ công</span>
            </div>

            {/* Quadrant 4: High Scam / High AI */}
            <div className={`border-b border-slate-800/80 p-3 transition-colors duration-300 flex flex-col justify-between ${
              activeQuadKey === 'q4' ? 'bg-amber-950/40 shadow-inner' : 'hover:bg-slate-900/30'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-amber-300 font-bold">Q4: AI Lừa Đảo / Deepfake</span>
                <span className="w-2 h-2 rounded-full bg-amber-500/80" />
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">Lừa đảo cao • AI tự động hóa</span>
            </div>

            {/* Quadrant 1: Low Scam / Low AI */}
            <div className={`border-r border-slate-800/80 p-3 transition-colors duration-300 flex flex-col justify-between ${
              activeQuadKey === 'q1' ? 'bg-emerald-950/40 shadow-inner' : 'hover:bg-slate-900/30'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-emerald-300 font-bold">Q1: Người Thật Lành Tính</span>
                <span className="w-2 h-2 rounded-full bg-emerald-500/80" />
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">An toàn tuyệt đối • Tự nhiên</span>
            </div>

            {/* Quadrant 2: Low Scam / High AI */}
            <div className={`p-3 transition-colors duration-300 flex flex-col justify-between ${
              activeQuadKey === 'q2' ? 'bg-sky-950/40 shadow-inner' : 'hover:bg-slate-900/30'
            }`}>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-sky-300 font-bold">Q2: AI Lành Tính / Tiện Ích</span>
                <span className="w-2 h-2 rounded-full bg-sky-500/80" />
              </div>
              <span className="text-[10px] text-slate-400 leading-tight">An toàn • Trợ lý AI hữu ích</span>
            </div>
          </div>

          {/* Active Coordinate Radar Ping Indicator */}
          <div
            className="absolute z-20 -translate-x-1/2 -translate-y-1/2 pointer-events-none transition-all duration-700 ease-out"
            style={{
              left: `${Math.min(90, Math.max(10, aiScore))}%`,
              top: `${Math.min(90, Math.max(10, 100 - scamScore))}%`,
            }}
          >
            <div className="relative flex items-center justify-center">
              {/* Radar pulse ping */}
              <span className={`animate-ping absolute inline-flex h-8 w-8 rounded-full ${pinGlowColor} opacity-75`} />
              {/* Outer halo */}
              <span className="relative inline-flex rounded-full h-5 w-5 bg-white border-2 border-slate-950 shadow-lg shadow-indigo-500/50 items-center justify-center">
                <span className={`w-2 h-2 rounded-full ${pinDotColor}`} />
              </span>
            </div>
          </div>
        </div>

        {/* Current Assessment Breakdown */}
        <div className="lg:col-span-5 space-y-3.5">
          <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 shadow-xs">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block mb-1 font-semibold">
              Vị Trí Định Danh Hiện Tại
            </span>
            <h4 className="text-sm font-semibold text-white tracking-tight">
              {activeTitle || 'Đánh giá Tọa độ An toàn'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed mt-1.5 font-normal">
              {activeExplanation || 'Kết quả phân tích định vị nội dung vào một trong bốn nhóm phân loại rõ ràng.'}
            </p>
          </div>

          {/* 4 Quadrant Interactive Badges */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className={`p-2.5 rounded-xl border transition-colors ${
              activeQuadKey === 'q1' 
                ? 'border-emerald-700 bg-emerald-950/40 text-emerald-200' 
                : 'border-slate-800/80 bg-slate-950/50 text-slate-400'
            }`}>
              <div className="flex items-center gap-1.5 mb-1 font-semibold text-[11px]">
                <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>Q1: Người Lành tính</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-tight">Liên lạc tự nhiên của người thật, an toàn.</p>
            </div>

            <div className={`p-2.5 rounded-xl border transition-colors ${
              activeQuadKey === 'q2' 
                ? 'border-sky-700 bg-sky-950/40 text-sky-200' 
                : 'border-slate-800/80 bg-slate-950/50 text-slate-400'
            }`}>
              <div className="flex items-center gap-1.5 mb-1 font-semibold text-[11px]">
                <Bot className="w-3.5 h-3.5 text-sky-400" />
                <span>Q2: AI Lành tính</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-tight">Thơ văn, tóm tắt do AI tạo, hữu ích.</p>
            </div>

            <div className={`p-2.5 rounded-xl border transition-colors ${
              activeQuadKey === 'q3' 
                ? 'border-rose-700 bg-rose-950/40 text-rose-200' 
                : 'border-slate-800/80 bg-slate-950/50 text-slate-400'
            }`}>
              <div className="flex items-center gap-1.5 mb-1 font-semibold text-[11px]">
                <UserX className="w-3.5 h-3.5 text-rose-400" />
                <span>Q3: Người Lừa đảo</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-tight">Bẫy thao túng tâm lý khẩn cấp, rất nguy hiểm.</p>
            </div>

            <div className={`p-2.5 rounded-xl border transition-colors ${
              activeQuadKey === 'q4' 
                ? 'border-amber-700 bg-amber-950/40 text-amber-200' 
                : 'border-slate-800/80 bg-slate-950/50 text-slate-400'
            }`}>
              <div className="flex items-center gap-1.5 mb-1 font-semibold text-[11px]">
                <Cpu className="w-3.5 h-3.5 text-amber-400" />
                <span>Q4: AI Lừa đảo</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-tight">Deepfake video/thoại giả mạo quy mô lớn.</p>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 flex items-start gap-2 pt-1 font-normal">
            <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <span className="leading-relaxed">
              <strong className="text-slate-300">Đặc tính toán học:</strong> Hai trục đánh giá trực giao đảm bảo hệ thống không đánh đồng việc "sử dụng AI" với "hành vi phạm tội".
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

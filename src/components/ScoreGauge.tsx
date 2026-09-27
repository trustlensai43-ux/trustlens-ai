import React from 'react';
import { AlertTriangle, Sparkles, CheckCircle2, ShieldAlert, Info, Shield } from 'lucide-react';

interface ScoreGaugeProps {
  type: 'scam' | 'ai';
  score: number;
  level: string;
  confidence?: number;
  evidenceCount?: number;
  summary: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  type,
  score,
  level,
  confidence,
  evidenceCount,
  summary,
}) => {
  const isScam = type === 'scam';

  // Determine semantic styling based on score and modality
  const getSemanticStyle = (val: number, isScamType: boolean) => {
    if (isScamType) {
      if (val >= 75) {
        return {
          border: 'border-rose-800/60 hover:border-rose-700/80',
          bg: 'bg-slate-900/80',
          metricText: 'text-rose-400',
          trackColor: '#f43f5e',
          glowFilter: 'drop-shadow(0 0 8px rgba(244, 63, 94, 0.45))',
          progressBar: 'bg-rose-500',
          badge: 'bg-rose-950/60 text-rose-300 border-rose-800/80',
          icon: ShieldAlert,
          iconColor: 'text-rose-400',
          iconBg: 'bg-rose-950/60 border-rose-800/60',
          glowBg: 'from-rose-500/10 via-transparent to-transparent',
        };
      }
      if (val >= 40) {
        return {
          border: 'border-amber-800/60 hover:border-amber-700/80',
          bg: 'bg-slate-900/80',
          metricText: 'text-amber-400',
          trackColor: '#f59e0b',
          glowFilter: 'drop-shadow(0 0 8px rgba(245, 158, 11, 0.45))',
          progressBar: 'bg-amber-500',
          badge: 'bg-amber-950/60 text-amber-300 border-amber-800/80',
          icon: AlertTriangle,
          iconColor: 'text-amber-400',
          iconBg: 'bg-amber-950/60 border-amber-800/60',
          glowBg: 'from-amber-500/10 via-transparent to-transparent',
        };
      }
      return {
        border: 'border-emerald-800/60 hover:border-emerald-700/80',
        bg: 'bg-slate-900/80',
        metricText: 'text-emerald-400',
        trackColor: '#10b981',
        glowFilter: 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.45))',
        progressBar: 'bg-emerald-500',
        badge: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/80',
        icon: CheckCircle2,
        iconColor: 'text-emerald-400',
        iconBg: 'bg-emerald-950/60 border-emerald-800/60',
        glowBg: 'from-emerald-500/10 via-transparent to-transparent',
      };
    } else {
      // AI Content probability (Uses sky/indigo tech accents)
      if (val >= 75) {
        return {
          border: 'border-sky-800/60 hover:border-sky-700/80',
          bg: 'bg-slate-900/80',
          metricText: 'text-sky-300',
          trackColor: '#38bdf8',
          glowFilter: 'drop-shadow(0 0 8px rgba(56, 189, 248, 0.45))',
          progressBar: 'bg-sky-500',
          badge: 'bg-sky-950/60 text-sky-300 border-sky-800/80',
          icon: Sparkles,
          iconColor: 'text-sky-400',
          iconBg: 'bg-sky-950/60 border-sky-800/60',
          glowBg: 'from-sky-500/10 via-transparent to-transparent',
        };
      }
      if (val >= 40) {
        return {
          border: 'border-indigo-800/60 hover:border-indigo-700/80',
          bg: 'bg-slate-900/80',
          metricText: 'text-indigo-300',
          trackColor: '#818cf8',
          glowFilter: 'drop-shadow(0 0 8px rgba(129, 140, 248, 0.45))',
          progressBar: 'bg-indigo-400',
          badge: 'bg-indigo-950/60 text-indigo-300 border-indigo-800/80',
          icon: Sparkles,
          iconColor: 'text-indigo-400',
          iconBg: 'bg-indigo-950/60 border-indigo-800/60',
          glowBg: 'from-indigo-500/10 via-transparent to-transparent',
        };
      }
      return {
        border: 'border-emerald-800/40 hover:border-emerald-700/60',
        bg: 'bg-slate-900/80',
        metricText: 'text-emerald-400',
        trackColor: '#10b981',
        glowFilter: 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.35))',
        progressBar: 'bg-emerald-500/80',
        badge: 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60',
        icon: CheckCircle2,
        iconColor: 'text-emerald-400',
        iconBg: 'bg-emerald-950/60 border-emerald-800/60',
        glowBg: 'from-emerald-500/5 via-transparent to-transparent',
      };
    }
  };

  const style = getSemanticStyle(score, isScam);
  const IconComponent = style.icon;

  // Arc math for SVG Radial Gauge
  // Circumference for r=42 is 2 * PI * 42 ≈ 263.89
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  // Use a 240-degree gauge (leaving a 120-degree gap at bottom)
  const arcLength = circumference * (240 / 360);
  const strokeOffset = arcLength - (arcLength * Math.min(100, Math.max(0, score))) / 100;

  return (
    <div className={`relative overflow-hidden p-5 md:p-6 rounded-2xl border ${style.border} ${style.bg} backdrop-blur-xl border-t border-t-white/10 shadow-2xl shadow-black/60 flex flex-col justify-between transition-all duration-300 group`}>
      {/* Subtle top-corner radial ambient flare */}
      <div className={`absolute -top-12 -right-12 w-44 h-44 rounded-full bg-gradient-to-br ${style.glowBg} blur-2xl pointer-events-none -z-10`} />

      <div>
        {/* Header Label */}
        <div className="flex items-center justify-between gap-2 mb-4">
          <div className="flex items-center gap-2.5">
            <div className={`w-7 h-7 rounded-lg ${style.iconBg} border flex items-center justify-center shrink-0`}>
              <IconComponent className={`w-4 h-4 ${style.iconColor} stroke-[2]`} />
            </div>
            <span className="text-xs uppercase tracking-wider font-mono font-semibold text-slate-200">
              {isScam ? 'Chỉ Số Nguy Cơ Lừa Đảo' : 'Chỉ Số Dấu Vết Cú Pháp AI'}
            </span>
          </div>
          <span className={`px-2.5 py-0.5 text-xs font-mono font-semibold border rounded-md shadow-xs ${style.badge}`}>
            {level}
          </span>
        </div>

        {/* Dial & Metric Showcase */}
        <div className="flex items-center gap-5 my-2">
          {/* High-Precision SVG Dial */}
          <div className="relative w-24 h-24 shrink-0 flex items-center justify-center">
            <svg
              className="w-full h-full transform -rotate-[210deg]"
              viewBox="0 0 100 100"
            >
              {/* Background Track */}
              <circle
                cx="50"
                cy="50"
                r={radius}
                fill="transparent"
                stroke="#1e293b"
                strokeWidth="7"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeLinecap="round"
              />
              {/* Active Meter Arc with soft glowing illumination */}
              <circle
                cx="50"
                cy="50"
                r={radius}
                fill="transparent"
                stroke={style.trackColor}
                strokeWidth="7"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeDashoffset={strokeOffset}
                strokeLinecap="round"
                style={{
                  filter: style.glowFilter,
                  transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
                }}
              />
            </svg>

            {/* Inner Centered Mini Metric */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className={`text-xl font-extrabold font-mono tabular-nums leading-none tracking-tight ${style.metricText}`}>
                {score}%
              </span>
              <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mt-0.5">
                Điểm
              </span>
            </div>
          </div>

          {/* Large Monospace Metric & Confidence Breakdown */}
          <div className="flex-1 space-y-1.5">
            <div className="flex items-baseline gap-2">
              <span className={`text-3xl sm:text-4xl font-extrabold font-mono tabular-nums tracking-tight ${style.metricText}`}>
                {score}
              </span>
              <span className="text-xs text-slate-500 font-mono font-medium">
                / 100 điểm
              </span>
            </div>

            <div className="flex items-center justify-between text-xs font-mono pt-1 border-t border-slate-800/80">
              <span className="text-slate-400">
                {evidenceCount !== undefined ? 'Bằng chứng xác thực:' : 'Độ tin cậy:'}
              </span>
              <span className="font-semibold text-slate-200 tabular-nums">
                {evidenceCount !== undefined ? `${evidenceCount} dấu hiệu đối soát` : `${confidence}%`}
              </span>
            </div>

            {/* Hairline Linear Progress Indicator */}
            <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800/80">
              <div
                className={`h-full ${style.progressBar} transition-all duration-700 ease-out`}
                style={{ width: `${Math.max(4, score)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Summary Description */}
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mt-3 font-normal">
          {summary}
        </p>
      </div>

      {/* Critical Orthogonal Context Note */}
      <div className="mt-4 pt-3.5 border-t border-slate-800/80 text-xs text-slate-400 flex items-start gap-2">
        <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
        <span className="leading-relaxed">
          {isScam ? (
            <>
              <strong className="text-slate-200 font-medium">Độc lập với AI:</strong> Kẻ lừa đảo tự gõ tay nội dung vẫn có thể tạo bẫy thao túng tâm lý 100%.
            </>
          ) : (
            <>
              <strong className="text-slate-200 font-medium">Chỉ Số Dấu Vết Cú Pháp AI:</strong> Phản ánh các đặc trưng cú pháp, cấu trúc ngữ pháp và nhịp điệu máy (độc lập với ý đồ lừa đảo hay lành tính).
            </>
          )}
        </span>
      </div>
    </div>
  );
};

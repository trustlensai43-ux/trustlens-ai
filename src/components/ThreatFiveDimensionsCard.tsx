import React from 'react';
import { 
  ShieldAlert, 
  Clock, 
  CreditCard, 
  Terminal, 
  Building2, 
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';
import { FiveDimensionalThreatAnalysis } from '../types';

interface ThreatFiveDimensionsCardProps {
  breakdown?: FiveDimensionalThreatAnalysis;
  scamScore: number;
}

export const ThreatFiveDimensionsCard: React.FC<ThreatFiveDimensionsCardProps> = ({
  breakdown,
  scamScore,
}) => {
  if (!breakdown) return null;

  const dimensions = breakdown?.dimensions;
  const detectedFlagsSummary = breakdown?.detectedFlagsSummary || 'Hệ thống đã hoàn tất quét 5 chiều hành vi rủi ro.';
  const ruleTriggered = breakdown?.ruleTriggered;
  const mandatoryWarning = breakdown?.mandatoryWarning;
  const allIndicators = breakdown?.indicators || [];
  const allTactics = breakdown?.tactics || [];

  const dimensionList = [
    {
      id: 'coercion',
      data: dimensions?.coercion,
      icon: Clock,
      color: (dimensions?.coercion?.score ?? 0) > 0 ? 'text-amber-400' : 'text-slate-400',
      barColor: 'bg-amber-500',
      badgeColor: (dimensions?.coercion?.score ?? 0) > 0 ? 'bg-amber-950/70 text-amber-300 border-amber-800' : 'bg-slate-900 text-slate-400 border-slate-800',
    },
    {
      id: 'financial',
      data: dimensions?.financial,
      icon: CreditCard,
      color: (dimensions?.financial?.score ?? 0) > 0 ? 'text-rose-400' : 'text-slate-400',
      barColor: 'bg-rose-500',
      badgeColor: (dimensions?.financial?.score ?? 0) > 0 ? 'bg-rose-950/70 text-rose-300 border-rose-800' : 'bg-slate-900 text-slate-400 border-slate-800',
    },
    {
      id: 'malware',
      data: dimensions?.malware,
      icon: Terminal,
      color: (dimensions?.malware?.score ?? 0) > 0 ? 'text-purple-400' : 'text-slate-400',
      barColor: 'bg-purple-500',
      badgeColor: (dimensions?.malware?.score ?? 0) > 0 ? 'bg-purple-950/70 text-purple-300 border-purple-800' : 'bg-slate-900 text-slate-400 border-slate-800',
    },
    {
      id: 'impersonation',
      data: dimensions?.impersonation,
      icon: Building2,
      color: (dimensions?.impersonation?.score ?? 0) > 0 ? 'text-sky-400' : 'text-slate-400',
      barColor: 'bg-sky-500',
      badgeColor: (dimensions?.impersonation?.score ?? 0) > 0 ? 'bg-sky-950/70 text-sky-300 border-sky-800' : 'bg-slate-900 text-slate-400 border-slate-800',
    },
    {
      id: 'harvesting',
      data: dimensions?.harvesting,
      icon: KeyRound,
      color: (dimensions?.harvesting?.score ?? 0) > 0 ? 'text-red-400' : 'text-slate-400',
      barColor: 'bg-red-500',
      badgeColor: (dimensions?.harvesting?.score ?? 0) > 0 ? 'bg-red-950/70 text-red-300 border-red-800' : 'bg-slate-900 text-slate-400 border-slate-800',
    },
  ];

  return (
    <div className="bg-slate-900/80 backdrop-blur-xl border border-slate-800/90 rounded-2xl p-5 md:p-6 shadow-2xl shadow-black/60 border-t border-t-white/10 space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Mô Hình 5 Chiều Nhận Diện Hành Vi Đe Dọa (5-Dimensional Behavioral Matrix)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Đánh giá hành vi độc lập trên 5 vector trực giao, không phụ thuộc vào từ khóa cứng.
          </p>
        </div>

        {ruleTriggered && (
          <span className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-slate-950 text-sky-300 border border-slate-800 self-start sm:self-auto">
            Quy tắc: {ruleTriggered}
          </span>
        )}
      </div>

      {/* Summary flags banner */}
      <div className={`p-4 rounded-xl border flex items-start gap-3 ${
        (scamScore ?? 0) >= 75 
          ? 'bg-rose-950/40 border-rose-900/70 text-rose-200' 
          : (scamScore ?? 0) >= 40 
          ? 'bg-amber-950/40 border-amber-900/70 text-amber-200' 
          : 'bg-slate-950/90 border-slate-800 text-slate-300'
      }`}>
        <Info className="w-4 h-4 shrink-0 mt-0.5 text-sky-400" />
        <div className="text-xs leading-relaxed">
          <strong className="font-semibold block mb-0.5 text-white">Tổng hợp bằng chứng phát hiện:</strong>
          {detectedFlagsSummary}
        </div>
      </div>

      {mandatoryWarning && (
        <div className="p-3.5 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
          <span className="leading-relaxed font-medium">{mandatoryWarning}</span>
        </div>
      )}

      {/* 5-Dimensional Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {dimensionList.map(({ id, data, icon: Icon, color, barColor, badgeColor }) => {
          const score = data?.score ?? 0;
          const isTriggered = score > 0;
          const signals = data?.signals || [];

          return (
            <div 
              key={id}
              className={`p-4 rounded-xl border transition-all duration-200 flex flex-col justify-between ${
                isTriggered 
                  ? 'bg-slate-950/90 border-slate-800/90 hover:border-slate-700' 
                  : 'bg-slate-950/40 border-slate-900 text-slate-500'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 ${color}`} />
                    <span className="text-xs font-semibold text-white">
                      {data?.name || id}
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 ${badgeColor}`}>
                    {data?.matchedCount ?? 0} tín hiệu
                  </span>
                </div>

                <p className="text-[11px] text-slate-300 leading-relaxed min-h-[32px]">
                  {data?.explanation || 'Không phát hiện bất thường ở chiều hành vi này.'}
                </p>

                {signals.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {signals.map((sig, sIdx) => (
                      <span 
                        key={sIdx}
                        className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-900 text-slate-300 border border-slate-800/80"
                      >
                        {sig}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-800/70">
                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                  <span>Trọng số: {Math.round((data?.weight ?? 0.2) * 100)}%</span>
                  <span className="font-bold text-white">{score}% rủi ro</span>
                </div>
                <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-slate-800">
                  <div 
                    className={`h-full ${barColor} transition-all duration-500`}
                    style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

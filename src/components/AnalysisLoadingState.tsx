import React, { useEffect, useState } from 'react';
import { ShieldCheck, Cpu, Search, Database, Check } from 'lucide-react';

interface AnalysisLoadingStateProps {
  modality: string;
}

const PIPELINE_STAGES = [
  {
    id: 1,
    title: 'Tiếp nhận & Tiền xử lý Dữ liệu',
    description: 'Kiểm tra mã hóa chuỗi, cấu trúc cú pháp và áp dụng quy tắc ẩn danh PII (CCCD, SĐT, STK).',
    icon: Database,
    durationMs: 900,
  },
  {
    id: 2,
    title: 'Thực thi Tập Heuristic Cố định',
    description: 'Quét từ khóa áp lực tâm lý, kiểm tra tên miền mạo danh thương hiệu và định dạng số điện thoại.',
    icon: Search,
    durationMs: 1400,
  },
  {
    id: 3,
    title: 'Giám định Đa phương thức Bằng Mô hình AI',
    description: 'Đánh giá bất thường thị giác, cấu trúc ngữ nghĩa, kịch bản thao túng và nhịp điệu phát âm.',
    icon: Cpu,
    durationMs: 1800,
  },
  {
    id: 4,
    title: 'Hiệu chỉnh Ma trận Tin cậy Trực giao',
    description: 'Đối chiếu độc lập Nguy cơ Lừa đảo (0–100%) và Xác suất AI (0–100%) kèm ngưỡng tin cậy.',
    icon: ShieldCheck,
    durationMs: 1200,
  },
];

export const AnalysisLoadingState: React.FC<AnalysisLoadingStateProps> = ({ modality }) => {
  const [currentStage, setCurrentStage] = useState(0);

  useEffect(() => {
    let timeout: NodeJS.Timeout;
    const advanceStage = (index: number) => {
      if (index < PIPELINE_STAGES.length - 1) {
        timeout = setTimeout(() => {
          setCurrentStage(index + 1);
          advanceStage(index + 1);
        }, PIPELINE_STAGES[index].durationMs);
      }
    };

    advanceStage(0);
    return () => clearTimeout(timeout);
  }, []);

  return (
    <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-8 max-w-2xl mx-auto shadow-lg text-center my-6">
      {/* Animated Pulsing Scanner Icon */}
      <div className="relative w-16 h-16 mx-auto mb-6 flex items-center justify-center">
        <span className="absolute inset-0 rounded-full bg-zinc-500/20 animate-ping duration-1000" />
        <div className="relative w-14 h-14 rounded-full bg-zinc-950 border border-zinc-500/40 flex items-center justify-center text-zinc-400 shadow-md">
          <Cpu className="w-7 h-7 animate-pulse text-zinc-400" />
        </div>
      </div>

      <h3 className="text-lg font-semibold text-zinc-100 tracking-tight">
        Hệ Thống Đang Thực Hiện Quy Trình Giám Định
      </h3>
      <p className="text-xs text-zinc-400 mt-1 max-w-md mx-auto">
        Đang phân tích dữ liệu dạng <span className="font-mono text-zinc-300 uppercase">{modality}</span> qua hệ thống quy tắc heuristic kết hợp mô hình AI đa phương thức.
      </p>

      {/* Pipeline Steps Tracker */}
      <div className="mt-8 space-y-4 text-left">
        {PIPELINE_STAGES.map((stage, idx) => {
          const isDone = idx < currentStage;
          const isCurrent = idx === currentStage;
          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`p-3.5 rounded-lg border transition-all ${
                isCurrent
                  ? 'bg-zinc-950/30 border-zinc-500/40 ring-1 ring-zinc-500/20'
                  : isDone
                  ? 'bg-zinc-950/60 border-zinc-800/80 opacity-80'
                  : 'bg-zinc-950/20 border-zinc-900 opacity-40'
              }`}
            >
              <div className="flex items-center gap-3">
                <div
                  className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-mono font-bold shrink-0 ${
                    isDone
                      ? 'bg-emerald-950 border border-emerald-700 text-emerald-400'
                      : isCurrent
                      ? 'bg-zinc-950 border border-zinc-600 text-zinc-300 animate-pulse'
                      : 'bg-zinc-900 border border-zinc-800 text-zinc-400'
                  }`}
                >
                  {isDone ? <Check className="w-3.5 h-3.5 stroke-[2.5]" /> : idx + 1}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-xs font-semibold tracking-tight ${
                        isCurrent
                          ? 'text-zinc-200'
                          : isDone
                          ? 'text-zinc-300'
                          : 'text-zinc-400'
                      }`}
                    >
                      {stage.title}
                    </span>
                    {isCurrent && (
                      <span className="text-[10px] uppercase font-mono text-zinc-400 animate-pulse">
                        Đang thực hiện...
                      </span>
                    )}
                    {isDone && (
                      <span className="text-[10px] uppercase font-mono text-emerald-400">
                        Hoàn thành
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-zinc-400 truncate mt-0.5">
                    {stage.description}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-6 pt-4 border-t border-zinc-800 text-[11px] text-zinc-400 flex items-center justify-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-zinc-400 animate-ping" />
        <span>Chính sách cách ly tuyệt đối: Không lưu trữ dữ liệu huấn luyện, áp dụng ẩn thông tin cá nhân PII.</span>
      </div>
    </div>
  );
};

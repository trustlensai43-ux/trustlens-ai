import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ChevronDown, 
  ChevronUp, 
  Lock, 
  Globe2, 
  ExternalLink,
  CheckCircle2,
  Smartphone
} from 'lucide-react';

interface GoldenSecurityRulesProps {
  defaultExpanded?: boolean;
  variant?: 'banner' | 'card';
  className?: string;
}

export const GoldenSecurityRules: React.FC<GoldenSecurityRulesProps> = ({
  defaultExpanded = true,
  className = '',
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(defaultExpanded);

  return (
    <div 
      id="golden-security-rules-card"
      className={`rounded-xl border border-zinc-800/60 bg-zinc-900/60 backdrop-blur-md shadow-xs overflow-hidden transition-colors duration-200 hover:border-zinc-700/80 ${className}`}
    >
      {/* Header bar with toggle */}
      <div 
        onClick={() => setIsExpanded(!isExpanded)}
        className="px-4 py-3.5 sm:px-5 flex items-center justify-between gap-3 cursor-pointer select-none bg-zinc-950/40 hover:bg-zinc-950/70 transition-colors border-b border-zinc-800/60"
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-amber-950/40 border border-amber-800/50 flex items-center justify-center text-amber-400 shrink-0">
            <ShieldAlert className="w-4 h-4 stroke-[1.75]" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-xs sm:text-sm font-semibold text-zinc-100 tracking-tight truncate">
                2 Quy Tắc "Vàng" Giúp Bạn Không Bao Giờ Bị Lừa
              </h3>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-amber-950/40 text-amber-300 border border-amber-800/40 shrink-0">
                Ghi Nhớ Nhanh
              </span>
            </div>
            <p className="text-[11px] text-zinc-400 truncate hidden sm:block font-normal">
              Chỉ cần nhớ 2 điều này, bạn và người thân sẽ tránh được hầu hết các vụ lừa đảo qua mạng.
            </p>
          </div>
        </div>

        <button
          type="button"
          aria-label={isExpanded ? 'Thu gọn nguyên tắc' : 'Mở rộng nguyên tắc'}
          className="p-1.5 rounded text-zinc-400 hover:text-zinc-200 shrink-0 transition-colors"
        >
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="p-4 sm:p-5 space-y-3.5 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Rule 1: Zero-Authority Credential Rule */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2.5 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 rounded-full bg-amber-950/60 border border-amber-800/60 text-amber-300 flex items-center justify-center font-mono font-bold text-[10px] shrink-0">
                    1
                  </div>
                  <Lock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <h4 className="font-semibold text-zinc-100 text-xs">
                    Quy Tắc 1: Mật Khẩu và Mã OTP Là Tuyệt Đối Bí Mật
                  </h4>
                </div>
                <div className="p-2.5 rounded bg-amber-950/20 border border-amber-900/40 text-amber-200/90 text-xs font-normal leading-relaxed">
                  "Các cơ quan nhà nước, ngân hàng, công an hay bệnh viện <strong>KHÔNG BAO GIỜ</strong> yêu cầu bạn đọc mã OTP hay mật khẩu qua điện thoại hoặc tin nhắn."
                </div>
                <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                  Mã OTP chính là chìa khóa mở két tiền của bạn. Bất cứ ai giục bạn đọc mã OTP hoặc gửi link bảo nhập OTP đều là kẻ lừa đảo.
                </p>
              </div>

              <div className="pt-2 border-t border-zinc-800/60 flex items-center gap-1.5 text-[10px] font-mono text-zinc-400">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>Tuyệt đối không đọc hay gửi mã OTP cho bất kỳ ai</span>
              </div>
            </div>

            {/* Rule 2: Typosquatting & URL Caution */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2.5 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 rounded-full bg-sky-950/60 border border-sky-800/60 text-sky-300 flex items-center justify-center font-mono font-bold text-[10px] shrink-0">
                    2
                  </div>
                  <Globe2 className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                  <h4 className="font-semibold text-zinc-100 text-xs">
                    Quy Tắc 2: Cảnh Giác Với Các Đường Link Lạ
                  </h4>
                </div>
                <div className="p-2.5 rounded bg-sky-950/20 border border-sky-900/40 text-sky-200/90 text-xs font-normal leading-relaxed">
                  "Không bấm vào các đường link lạ gửi qua tin nhắn. Website chính thống của cơ quan nhà nước Việt Nam luôn có đuôi <span className="font-mono text-emerald-300">.gov.vn</span>."
                </div>
                <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                  Kẻ gian thường làm website nhái giống hệt giao diện ngân hàng hoặc dịch vụ công. Khi cần giao dịch, hãy tự mở ứng dụng trên điện thoại hoặc tự gõ địa chỉ web.
                </p>
              </div>

              <div className="pt-2 border-t border-zinc-800/60 flex items-center gap-1.5 text-[10px] font-mono text-zinc-400">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>Chỉ tin cậy website chính thức và ứng dụng từ cửa hàng CH Play / App Store</span>
              </div>
            </div>
          </div>

          {/* Quick Action Recommendations */}
          <div className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-zinc-300">
              <Smartphone className="w-4 h-4 text-emerald-400 shrink-0" />
              <span className="font-normal text-zinc-300">
                Khuyến nghị: Cài đặt ứng dụng <strong>nTrust</strong> (Hiệp hội An ninh mạng quốc gia) để tự động phát hiện số tài khoản lừa đảo và số điện thoại mạo danh.
              </span>
            </div>

            <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
              <a
                href="https://ntrust.vn"
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-[11px] font-mono flex items-center gap-1 transition-colors active:scale-[0.98]"
              >
                <span>Tải nTrust</span>
                <ExternalLink className="w-3 h-3 text-zinc-500" />
              </a>

              <a
                href="https://tinnhiemmang.vn"
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 text-[11px] font-mono flex items-center gap-1 transition-colors active:scale-[0.98]"
              >
                <span>Tín Nhiệm Mạng</span>
                <ExternalLink className="w-3 h-3 text-zinc-500" />
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

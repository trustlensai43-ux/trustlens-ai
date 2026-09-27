import React, { useState } from 'react';
import { 
  AlertTriangle, 
  PhoneCall, 
  Camera, 
  ExternalLink, 
  ShieldAlert, 
  Copy, 
  Check, 
  Building2, 
  BadgeAlert,
  ChevronDown,
  ChevronUp,
  FileText,
  Globe2,
  Smartphone,
  ShieldCheck
} from 'lucide-react';

interface VietnamActionGuideProps {
  scamScore: number;
  inputContent?: string;
  indicators?: Array<{ category?: string; description?: string; title?: string }>;
}

export const VietnamActionGuide: React.FC<VietnamActionGuideProps> = ({
  scamScore,
  inputContent = '',
  indicators = [],
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  // Chỉ hiển thị hướng dẫn ứng phó khẩn cấp khi mức độ rủi ro lừa đảo từ 50 trở lên (Mức Cao hoặc Rất Cao)
  if (scamScore < 50) {
    return null;
  }

  // Kiểm tra điều kiện xuất hiện của Tổng đài 111: Chỉ kích hoạt khi có dấu hiệu nhắm vào trẻ em / vị thành niên
  const lowerContent = inputContent.toLowerCase();
  const indicatorTexts = indicators.map(i => `${i.title || ''} ${i.description || ''}`).join(' ').toLowerCase();
  const fullText = `${lowerContent} ${indicatorTexts}`;
  
  const isMinorExploitation = 
    fullText.includes('trẻ em') || 
    fullText.includes('học sinh') || 
    fullText.includes('con bạn đang cấp cứu') || 
    fullText.includes('bắt cóc') || 
    fullText.includes('trường học') || 
    fullText.includes('con nằm viện') ||
    fullText.includes('vị thành niên');

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="rounded-xl border border-rose-800/40 bg-zinc-900/60 backdrop-blur-md p-5 shadow-xs space-y-4 transition-colors duration-200 hover:border-rose-700/60">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800/60">
        <div className="flex items-start sm:items-center gap-2.5">
          <div className="p-2 rounded-lg bg-rose-950/40 text-rose-400 border border-rose-800/50 shrink-0">
            <BadgeAlert className="w-5 h-5 stroke-[2]" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="text-sm font-semibold text-rose-200 tracking-tight">
                Những Việc Bạn Nên Làm Ngay Lúc Này Để Tự Bảo Vệ
              </h4>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-950/60 text-rose-300 border border-rose-800/60 tabular-nums">
                Mức độ rủi ro: {scamScore}/100
              </span>
            </div>
            <p className="text-xs text-zinc-400 mt-0.5 leading-relaxed font-normal">
              Bình tĩnh thực hiện theo các bước dưới đây để bảo vệ tài sản và tránh bị kẻ xấu thao túng.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-xs font-mono text-zinc-400 hover:text-zinc-200 flex items-center gap-1 self-end sm:self-auto shrink-0 transition-colors cursor-pointer"
        >
          <span>{isExpanded ? 'Thu gọn' : 'Xem hướng dẫn xử lý'}</span>
          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {isExpanded && (
        <div className="space-y-4">
          {/* 4-Step Crisis Roadmap */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* BƯỚC 1: XỬ LÝ TÀI CHÍNH */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-rose-950/60 border border-rose-800/60 text-rose-300 flex items-center justify-center text-[11px] font-mono font-bold shrink-0">
                  1
                </span>
                <Building2 className="w-4 h-4 text-rose-400 shrink-0" />
                <h5 className="text-xs font-semibold text-zinc-100">
                  Bước 1: Gọi Ngay Ngân Hàng Để Tạm Khóa Thẻ / Tài Khoản
                </h5>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                Nếu đã lỡ bấm vào link lạ hoặc chuyển tiền: <strong>Hãy gọi ngay tổng đài ngân hàng của bạn</strong> (số in ở mặt sau thẻ ATM hoặc trong ứng dụng ngân hàng) để:
              </p>
              <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                <li>Khóa tạm thời tính năng giao dịch trực tuyến và khóa thẻ ngay lập tức.</li>
                <li>Yêu cầu ghi nhận tra soát giao dịch gian lận để phối hợp phong tỏa dòng tiền.</li>
              </ul>
            </div>

            {/* BƯỚC 2: BẢO TỒN CHỨNG CỨ */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-amber-950/60 border border-amber-800/60 text-amber-300 flex items-center justify-center text-[11px] font-mono font-bold shrink-0">
                  2
                </span>
                <Camera className="w-4 h-4 text-amber-400 shrink-0" />
                <h5 className="text-xs font-semibold text-zinc-100">
                  Bước 2: Chụp Lại Màn Hình & Giữ Nguyên Bằng Chứng
                </h5>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                Không xóa tin nhắn hay tranh cãi để kẻ gian không xóa dấu vết:
              </p>
              <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                <li>Chụp lại toàn bộ màn hình tin nhắn, số điện thoại người gọi, đường link web.</li>
                <li>Lưu lại biên lai chuyển khoản có mã giao dịch (mã tham chiếu) nếu đã chuyển tiền.</li>
              </ul>
            </div>

            {/* BƯỚC 3: PHẢN ÁNH CUỘC GỌI / TIN NHẮN RÁC & LỪA ĐẢO */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-zinc-900 border border-zinc-700 text-zinc-300 flex items-center justify-center text-[11px] font-mono font-bold shrink-0">
                  3
                </span>
                <PhoneCall className="w-4 h-4 text-zinc-300 shrink-0" />
                <h5 className="text-xs font-semibold text-zinc-100">
                  Bước 3: Báo Cáo Tin Nhắn / Cuộc Gọi Rác Tới Tổng Đài 156
                </h5>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                Phản ánh miễn phí số điện thoại hoặc tin nhắn lừa đảo tới cơ quan chức năng:
              </p>
              <div className="space-y-1.5 pt-1 text-[11px] font-mono">
                <div className="flex items-center justify-between p-2 rounded bg-zinc-950 border border-zinc-800/80">
                  <span className="text-zinc-300">Gọi miễn phí: <strong>156</strong></span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard('156', 'call-156')}
                    className="text-zinc-400 hover:text-zinc-200 flex items-center gap-1 text-[10px] active:scale-[0.98] transition-all"
                  >
                    {copiedKey === 'call-156' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'call-156' ? 'Đã chép' : 'Sao chép'}</span>
                  </button>
                </div>
                <div className="p-2 rounded bg-zinc-950 border border-zinc-800/80 text-zinc-300">
                  Nhắn tin: <strong>V [Số ĐT lừa đảo] [Nội dung]</strong> gửi <strong>156</strong> hoặc <strong>5656</strong>
                </div>
                <div className="pt-0.5">
                  <a
                    href="https://nospam.vncert.vn/"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-zinc-300 hover:text-zinc-100 underline text-[11px] transition-colors"
                  >
                    <span>Cổng phản ánh trực tuyến nospam.vncert.vn</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            </div>

            {/* BƯỚC 4: TRÌNH BÁO TỘI PHẠM QUA VNeID HOẶC CÔNG AN */}
            <div className="p-4 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-zinc-900 border border-zinc-700 text-zinc-300 flex items-center justify-center text-[11px] font-mono font-bold shrink-0">
                  4
                </span>
                <ShieldAlert className="w-4 h-4 text-zinc-300 shrink-0" />
                <h5 className="text-xs font-semibold text-zinc-100">
                  Bước 4: Tố Giác Tội Phạm Hình Sự (VNeID & Công An)
                </h5>
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                Thực hiện nộp đơn tố giác tội phạm công nghệ cao theo 2 phương thức hợp lệ:
              </p>
              <ul className="text-[11px] text-zinc-400 space-y-1 list-disc list-inside">
                <li>
                  <strong>Qua ứng dụng VNeID:</strong> Mở VNeID → Chọn mục <em>"Dịch vụ khác"</em> → Chọn <em>"Kiến nghị, phản ánh về ANTT"</em> → Nộp thông tin và ảnh chụp chứng cứ.
                </li>
                <li>
                  <strong>Trực tiếp tại địa bàn:</strong> Mang đầy đủ bản in chứng cứ và sao kê ngân hàng đến <strong>Công an phường/xã</strong> nơi bạn cư trú để lập biên bản tiếp nhận tố giác tội phạm.
                </li>
              </ul>
            </div>
          </div>

          {/* CHỈ HIỂN THỊ KHI CÓ DẤU HIỆU LIÊN QUAN ĐẾN TRẺ EM / VỊ THÀNH NIÊN */}
          {isMinorExploitation && (
            <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/40 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div className="text-xs space-y-1">
                <span className="font-semibold text-amber-200 block">
                  Cảnh báo Kịch bản Lừa đảo Nhắm vào Học sinh / Trẻ em:
                </span>
                <p className="text-zinc-300 leading-relaxed font-normal">
                  Trường hợp nghi vấn hành vi dụ dỗ, đe dọa, tống tiền hoặc kịch bản giả mạo "con đang cấp cứu tại bệnh viện", hãy liên hệ ngay <strong>Tổng đài Quốc gia Bảo vệ Trẻ em 111</strong> (miễn phí cước gọi 24/7) để nhận hỗ trợ bảo vệ tâm lý và can thiệp khẩn cấp.
                </p>
              </div>
            </div>
          )}

          {/* CỔNG DANH BẠ AN TOÀN SỐ VIỆT NAM (VIETNAMESE DIGITAL SAFETY DIRECTORY) */}
          <div className="pt-3.5 border-t border-zinc-800/60 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <h5 className="text-xs font-semibold text-zinc-100 uppercase font-mono tracking-wider">
                  Hệ Thống Tra Cứu & Xác Minh An Toàn Số Quốc Gia
                </h5>
              </div>
              <span className="text-[10px] font-mono text-zinc-500">
                Nguồn lực chính thức & cộng đồng uy tín
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
              {/* Pillar A: Website & Domain Verification */}
              <div className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2 flex flex-col justify-between">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-medium uppercase px-1.5 py-0.2 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
                      Tên Miền & Website
                    </span>
                    <Globe2 className="w-3.5 h-3.5 text-zinc-500" />
                  </div>
                  <h6 className="text-xs font-semibold text-zinc-100">
                    Xác Minh Website & Tên Miền
                  </h6>
                  <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                    Đối soát tính chính thống của trang web, nhận diện cổng giả mạo ngân hàng và danh sách đen quốc gia.
                  </p>
                </div>

                <div className="space-y-1.5 pt-1 text-xs">
                  <a
                    href="https://tinnhiemmang.vn/tra-cuu-tinh-nhiem-mang"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 flex items-center justify-between text-zinc-300 hover:text-zinc-100 transition-colors group active:scale-[0.98]"
                  >
                    <span className="text-[11px] font-medium">Tín Nhiệm Mạng (NCSC)</span>
                    <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-zinc-200" />
                  </a>

                  <a
                    href="https://chongluadao.vn"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 flex items-center justify-between text-zinc-300 hover:text-zinc-100 transition-colors group active:scale-[0.98]"
                  >
                    <span className="text-[11px] font-medium">Chống Lừa Đảo (chongluadao.vn)</span>
                    <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-zinc-200" />
                  </a>
                </div>
              </div>

              {/* Pillar B: Spam, Calls & SMS Reporting */}
              <div className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2 flex flex-col justify-between">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-medium uppercase px-1.5 py-0.2 rounded bg-amber-950/40 text-amber-400 border border-amber-800/40">
                      Cuộc Gọi & Tin Nhắn
                    </span>
                    <PhoneCall className="w-3.5 h-3.5 text-zinc-500" />
                  </div>
                  <h6 className="text-xs font-semibold text-zinc-100">
                    Phản Ánh & Tra Cứu Số Lạ
                  </h6>
                  <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                    Báo cáo số điện thoại quấy rối, mạo danh cơ quan nhà nước và tra cứu danh bạ cộng đồng.
                  </p>
                </div>

                <div className="space-y-1.5 pt-1 text-xs">
                  <a
                    href="https://nospam.vncert.vn"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 flex items-center justify-between text-zinc-300 hover:text-zinc-100 transition-colors group active:scale-[0.98]"
                  >
                    <span className="text-[11px] font-medium">Cổng nospam VNCERT (156)</span>
                    <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-zinc-200" />
                  </a>

                  <a
                    href="https://trangtrang.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded bg-zinc-900/60 border border-zinc-800 hover:border-zinc-700 flex items-center justify-between text-zinc-300 hover:text-zinc-100 transition-colors group active:scale-[0.98]"
                  >
                    <span className="text-[11px] font-medium">Danh Bạ Trang Trắng</span>
                    <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-zinc-200" />
                  </a>
                </div>
              </div>

              {/* Pillar C: Specialized National Anti-Scam Mobile App */}
              <div className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors space-y-2 flex flex-col justify-between">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-medium uppercase px-1.5 py-0.2 rounded bg-sky-950/40 text-sky-400 border border-sky-800/40">
                      App Quốc Gia
                    </span>
                    <Smartphone className="w-3.5 h-3.5 text-zinc-500" />
                  </div>
                  <h6 className="text-xs font-semibold text-zinc-100">
                    Ứng Dụng nTrust (Hiệp Hội NCA)
                  </h6>
                  <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                    Ứng dụng di động kiểm tra trực tiếp số tài khoản ngân hàng lừa đảo, số điện thoại và đường link nguy hiểm.
                  </p>
                </div>

                <div className="pt-1">
                  <a
                    href="https://ntrust.vn"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full p-2 rounded bg-zinc-900/60 border border-zinc-700 hover:bg-zinc-800 flex items-center justify-center gap-1.5 text-zinc-200 text-xs font-medium transition-colors group active:scale-[0.98]"
                  >
                    <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Tải App nTrust (iOS & Android)</span>
                    <ExternalLink className="w-3 h-3 text-zinc-400 group-hover:text-zinc-200" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Disclaimers & Legal Notice */}
          <div className="text-[11px] text-zinc-500 flex items-center gap-2 pt-1 border-t border-zinc-800/60 font-mono">
            <FileText className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
            <span>
              TrustLens AI là nền tảng hỗ trợ sàng lọc và nâng cao nhận thức an toàn số. Kết quả phân tích không thay thế cho kết luận điều tra chính thức của cơ quan tiến hành tố tụng.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

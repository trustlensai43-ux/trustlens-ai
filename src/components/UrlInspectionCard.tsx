import React from 'react';
import { AnalysisResult } from '../types';
import { inspectUrl, buildExternalAuthorityLinks } from '../utils/urlInspector';
import { 
  Globe2, 
  ExternalLink, 
  ShieldCheck, 
  AlertTriangle, 
  Info,
  Search,
  Smartphone
} from 'lucide-react';

interface UrlInspectionCardProps {
  result: AnalysisResult;
}

export const UrlInspectionCard: React.FC<UrlInspectionCardProps> = ({ result }) => {
  const targetUrl = result.inputMetadata?.url || result.rawInputSnippet || result.inputSummary || '';
  const inspection = inspectUrl(targetUrl);
  const externalLinks = buildExternalAuthorityLinks(inspection.hostname);

  // Kiểm tra xem tên miền có TLD thuộc nhóm tự động giá rẻ không
  const isGenericTld = inspection.isCommonNewTld;

  return (
    <div className="bg-zinc-900/60 backdrop-blur-md border border-zinc-800/60 rounded-xl overflow-hidden shadow-xs space-y-4 p-5 hover:border-zinc-700/80 transition-colors duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-zinc-950/80 border border-zinc-800/80 flex items-center justify-center text-zinc-300">
            <Globe2 className="w-4 h-4 text-zinc-300" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
              <span>Giám Định Cấu Trúc Tên Miền & Xác Minh Cơ Quan</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-zinc-950 text-zinc-400 border border-zinc-800">
                RFC 3986
              </span>
            </h3>
            <p className="text-xs text-zinc-400 font-normal">
              Kiểm tra dấu hiệu giả mạo ký tự, phân tích TLD và cung cấp cổng tra cứu đối soát chính thức.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-zinc-500">Mục tiêu:</span>
          <span className="text-xs font-mono font-medium text-zinc-200 bg-zinc-950/80 px-2 py-0.5 rounded border border-zinc-800/80 break-all max-w-[260px] truncate">
            {inspection.hostname || targetUrl}
          </span>
        </div>
      </div>

      {/* TLD Calibration & Anti-False-Positive Notice */}
      <div className="p-3.5 rounded-lg border border-zinc-800/60 bg-zinc-950/60 text-xs">
        <div className="flex items-start gap-2.5">
          <Info className="w-4 h-4 text-zinc-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-zinc-200">
                Cơ chế Kiểm soát Trọng số TLD (.xyz, .top, .site)
              </span>
              <span className="px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-700/80 text-zinc-300 text-[10px] font-mono">
                Giới hạn tối đa: 10-15 điểm
              </span>
            </div>
            <p className="text-zinc-400 leading-relaxed text-[11px] font-normal">
              Để ngăn ngừa tuyệt đối tình trạng báo động sai (False Positives), TrustLens AI không bao giờ đánh giá một tên miền là rủi ro cao chỉ vì đuôi TLD. Ví dụ: tên miền hợp lệ như <span className="font-mono text-zinc-300 font-medium">abc.xyz</span> (trang chủ Alphabet/Google) luôn được đánh giá an toàn ở mức <span className="text-emerald-400 font-semibold font-mono">RỦI RO THẤP</span> khi không phát hiện hành vi mạo danh hay kịch bản lừa đảo.
            </p>
          </div>
        </div>
      </div>

      {/* Domain Breakdown Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
        <div className="p-3 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors">
          <span className="text-[10px] text-zinc-500 block uppercase mb-0.5">Tên Miền (Host)</span>
          <span className="text-zinc-200 truncate block font-medium" title={inspection.hostname}>
            {inspection.hostname || 'N/A'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors">
          <span className="text-[10px] text-zinc-500 block uppercase mb-0.5">Phần Mở Rộng (TLD)</span>
          <span className="text-zinc-200 block font-medium">
            {inspection.tld || 'N/A'} {isGenericTld && <span className="text-zinc-400 text-[10px] font-normal">(Generic)</span>}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors">
          <span className="text-[10px] text-zinc-500 block uppercase mb-0.5">Ký Tự Punycode</span>
          <span className={`font-semibold ${inspection.isPunycode ? 'text-rose-400' : 'text-emerald-400'}`}>
            {inspection.isPunycode ? 'Phát Hiện (Bất Thường)' : 'Bình Thường (ASCII)'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 transition-colors">
          <span className="text-[10px] text-zinc-500 block uppercase mb-0.5">Địa Chỉ IP Trực Tiếp</span>
          <span className={`font-semibold ${inspection.isIpAddress ? 'text-amber-400' : 'text-zinc-300'}`}>
            {inspection.isIpAddress ? 'Có (Dùng IP Thô)' : 'Không (Dùng DNS)'}
          </span>
        </div>
      </div>

      {/* Real-time Threat Intelligence / Blacklist Status Tag (UNAVAILABLE) */}
      <div className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-zinc-400" />
            <span className="text-xs font-semibold text-zinc-200">
              Đối Soát Danh Sách Đen Thời Gian Thực (Domain Blacklist Feed)
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-normal">
            Chưa đối soát danh sách đen thời gian thực (Khuyến nghị tra cứu tại Tín Nhiệm Mạng).
          </p>
        </div>

        <div className="shrink-0 flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700/80 text-[11px] font-mono text-zinc-400 uppercase font-medium flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
            <span>Chưa Kết Nối Feed</span>
          </span>
        </div>
      </div>

      {/* External Authority Verification Links */}
      <div className="space-y-2.5 pt-1">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-zinc-200 uppercase font-mono tracking-wider flex items-center gap-1.5">
            <Search className="w-3.5 h-3.5 text-zinc-400" />
            <span>Cổng Tra Cứu & Xác Minh Ngoại Bộ Chính Thống</span>
          </span>
          <span className="text-[10px] text-zinc-500 font-mono">
            Khuyến nghị tra cứu trực tiếp trước khi giao dịch
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Link 1: Tín Nhiệm Mạng */}
          <a
            id="link-tin-nhiem-mang"
            href={externalLinks.tinNhiemMang.url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all flex flex-col justify-between group active:scale-[0.98]"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Tín Nhiệm Mạng Quốc Gia</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 shrink-0" />
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                Tra cứu danh bạ website và tổ chức được chứng nhận an toàn bởi NCSC.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[10px] font-mono text-zinc-500 flex items-center gap-1">
              <span>tinnhiemmang.vn</span>
            </div>
          </a>

          {/* Link 2: Cổng Cảnh Báo An Toàn Không Gian Mạng */}
          <a
            id="link-canh-bao-khong-gian-mang"
            href={externalLinks.canhBaoKhongGianMang.url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all flex flex-col justify-between group active:scale-[0.98]"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>Cảnh Báo Không Gian Mạng</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 shrink-0" />
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                Đối soát danh sách đen các trang web lừa đảo và số tài khoản gian lận do AIS cảnh báo.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[10px] font-mono text-zinc-500 flex items-center gap-1">
              <span>canhbao.khonggianmang.vn</span>
            </div>
          </a>

          {/* Link 3: VirusTotal Lookup */}
          <a
            id="link-virustotal"
            href={externalLinks.virusTotal.url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all flex flex-col justify-between group active:scale-[0.98]"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center gap-1.5">
                  <Globe2 className="w-3.5 h-3.5 text-sky-400" />
                  <span>VirusTotal Intelligence</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 shrink-0" />
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                Kiểm tra kết quả quét độc hại từ hơn 70 engine an ninh mạng toàn cầu cho tên miền.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[10px] font-mono text-zinc-500 flex items-center gap-1">
              <span>virustotal.com/gui/domain</span>
            </div>
          </a>

          {/* Link 4: Chống Lừa Đảo */}
          <a
            id="link-chongluadao"
            href={externalLinks.chongLuaDao.url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all flex flex-col justify-between group active:scale-[0.98]"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Dự Án Chống Lừa Đảo</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 shrink-0" />
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                Tiện ích cộng đồng bảo trợ bởi NCSC giúp tự động phát hiện và chặn website phishing.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[10px] font-mono text-zinc-500 flex items-center gap-1">
              <span>chongluadao.vn</span>
            </div>
          </a>

          {/* Link 5: Ứng dụng nTrust */}
          <a
            id="link-ntrust-app"
            href={externalLinks.nTrust.url}
            target="_blank"
            rel="noopener noreferrer"
            className="p-3.5 rounded-lg bg-zinc-950/60 border border-zinc-800/60 hover:border-zinc-700/80 hover:bg-zinc-900/40 transition-all flex flex-col justify-between group md:col-span-2 active:scale-[0.98]"
          >
            <div>
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100 flex items-center gap-1.5">
                  <Smartphone className="w-3.5 h-3.5 text-sky-400" />
                  <span>Ứng Dụng Phòng Chống Lừa Đảo Quốc Gia (nTrust - NCA)</span>
                </span>
                <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 shrink-0" />
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-normal">
                Ứng dụng chính thức của Hiệp hội An ninh mạng quốc gia: Tra cứu danh sách đen tài khoản ngân hàng lừa đảo, số điện thoại lạ và tự động phát hiện liên kết độc hại trên smartphone.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[10px] font-mono text-zinc-500 flex items-center gap-1">
              <span>ntrust.vn • Tải miễn phí trên iOS & Android</span>
            </div>
          </a>
        </div>
      </div>
    </div>
  );
};

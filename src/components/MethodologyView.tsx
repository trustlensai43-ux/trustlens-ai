import React from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  FileText, 
  Scale, 
  Lock, 
  AlertTriangle, 
  CheckCircle2, 
  Info,
  ExternalLink 
} from 'lucide-react';

export const MethodologyView: React.FC = () => {
  return (
    <div className="space-y-8 max-w-4xl mx-auto py-2">
      {/* Header */}
      <div className="border-b border-zinc-800 pb-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-zinc-400" />
          <h2 className="text-xl font-semibold text-zinc-100 tracking-tight">
            Phương Pháp Luận Khoa Học & Kiến Trúc Niềm Tin Số
          </h2>
        </div>
        <p className="text-xs text-zinc-400 mt-1.5 leading-relaxed">
          Đặc tả kỹ thuật, mô hình hiệu chuẩn sai số và các nguyên tắc thiết kế đạo đức điều hành công cụ giám định TrustLens AI.
        </p>
      </div>

      {/* Principle 1: The Orthogonal Dual-Score Model */}
      <section className="space-y-3 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2">
          <Scale className="w-5 h-5 text-zinc-400" />
          <h3 className="text-base font-semibold text-zinc-100">
            1. Nguyên Tắc Trực Giao: Tách Biệt Nguồn Gốc (Origin) và Ý Đồ (Intent)
          </h3>
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed font-normal">
          Sai lầm phổ biến của các công cụ phòng chống lừa đảo truyền thống là đồng nhất <strong className="text-zinc-100">Nguồn gốc do AI tạo ra</strong> với <strong className="text-zinc-100">Ý đồ lừa đảo</strong>. Một bức thư điện tử hợp pháp được tóm tắt bởi LLM có thể chứa 100% văn phong AI nhưng hoàn toàn không có rủi ro lừa đảo. Ngược lại, một email lừa đảo chuyển khoản do tội phạm con người trực tiếp soạn thảo mang 100% rủi ro lừa đảo dù không có bất kỳ dấu hiệu AI nào.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4 text-xs">
          <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800">
            <span className="font-mono font-semibold text-rose-400 block mb-1">
              Nguy Cơ Lừa Đảo & Gian Lận (0–100%)
            </span>
            <p className="text-zinc-400 text-[11px] leading-relaxed">
              Đo lường sự hiện diện của các kỹ thuật thao túng tâm lý (Social Engineering): tạo áp lực thời gian, bẫy thu thập thông tin thẻ, yêu cầu chuyển khoản, mạo danh cơ quan và các phương thức thanh toán không thể hoàn hồi.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800">
            <span className="font-mono font-semibold text-zinc-400 block mb-1">
              Xác Suất Nội Dung Do AI Tạo/Can Thiệp (0–100%)
            </span>
            <p className="text-zinc-400 text-[11px] leading-relaxed">
              Đo lường dấu vết văn phong và thị giác nhân tạo: tính đồng nhất từ ngữ, dị thường khuếch tán hình ảnh, rung viền deepfake và các khiếm khuyết trong tổng hợp giọng nói.
            </p>
          </div>
        </div>
      </section>

      {/* Principle 2: Calibrated Uncertainty & No False Claims */}
      <section className="space-y-3 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <h3 className="text-base font-semibold text-zinc-100">
            2. Hiệu Chuẩn Khoa Học & Giới Hạn Xác Suất (Chuẩn NIST AI RMF 1.0)
          </h3>
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed font-normal">
          TrustLens AI tuân thủ nghiêm ngặt Khung quản lý rủi ro Trí tuệ nhân tạo của NIST. Không có hệ thống phát hiện AI xác suất nào có thể đảm bảo chính xác 100%. Hệ thống của chúng tôi cam kết:
        </p>

        <ul className="space-y-2 text-xs text-zinc-300">
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              <strong className="text-zinc-100">Trích Dẫn Bằng Chứng Cụ Thể:</strong> Mọi dấu hiệu cảnh báo đều phải đối chiếu với một trích dẫn nguyên văn, dị thường header hoặc chuỗi con URL rõ ràng.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              <strong className="text-zinc-100">Khoảng Tin Cậy Hiệu Chuẩn:</strong> Điểm số phản ánh xác suất thống kê và luôn nêu rõ các hạn chế kỹ thuật đối với từng trường hợp biên.
            </span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>
              <strong className="text-zinc-100">Khuyến Nghị Xác Minh Độc Lập:</strong> Nền tảng hướng dẫn người dùng thực hiện các bước xác minh kênh ngoài (Out-of-band) thay vì khẳng định kết luận tuyệt đối.
            </span>
          </li>
        </ul>
      </section>

      {/* Principle 3: Multi-modal Forensics Architecture */}
      <section className="space-y-3 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-zinc-400" />
          <h3 className="text-base font-semibold text-zinc-100">
            3. Kiến Trúc Đường Ống Đa Phương Thức (Pipeline)
          </h3>
        </div>

        <div className="space-y-2 text-xs">
          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
            <span className="font-semibold text-zinc-300 block mb-0.5">
              Lớp 1: Động Cơ Heuristic Xác Định (Deterministic Engine)
            </span>
            <p className="text-zinc-400">
              Phân tích cấu trúc RFC 5322 email header, bộ ký tự giả mạo (punycode/homoglyph) trong URL, độ đo entropy tên miền, danh sách TLD rủi ro cao và đầu số viễn thông.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
            <span className="font-semibold text-zinc-300 block mb-0.5">
              Lớp 2: Suy Luận Đa Phương Thức Gemini
            </span>
            <p className="text-zinc-400">
              Trích xuất sắc thái ngữ cảnh, phát hiện thao túng tâm lý khẩn cấp, phân tích dị thường thị giác và phân loại các kịch bản lừa đảo phức tạp.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
            <span className="font-semibold text-zinc-300 block mb-0.5">
              Lớp 3: Hiệu Chuẩn & Tổng Hợp Biện Pháp Ứng Phó
            </span>
            <p className="text-zinc-400">
              Hài hòa kết quả vào mô hình ma trận trực giao 4 góc phần tư và ánh xạ các biện pháp phòng ngừa an toàn theo khuyến nghị của Cục An toàn thông tin (NCSC/AIS) và FTC.
            </p>
          </div>
        </div>
      </section>

      {/* Principle 4: Privacy & Client Isolation */}
      <section className="space-y-3 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2">
          <Lock className="w-5 h-5 text-emerald-400" />
          <h3 className="text-base font-semibold text-zinc-100">
            4. Bảo Mật & Chính Sách Không Lưu Trữ Dữ Liệu (Zero-Retention)
          </h3>
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed font-normal">
          TrustLens AI tích hợp tính năng che dấu thông tin cá nhân (PII) ngay tại trình duyệt trước khi gửi đi phân tích. Lịch sử giám định hoàn toàn nằm trong bộ nhớ thiết bị của bạn và có thể xóa vĩnh viễn bằng một cú nhấp chuột.
        </p>
      </section>
    </div>
  );
};

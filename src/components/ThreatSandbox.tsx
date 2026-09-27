import React, { useState } from 'react';
import { 
  ShieldAlert, 
  MessageSquare, 
  PhoneCall, 
  Globe, 
  QrCode, 
  Users, 
  Briefcase, 
  Check, 
  AlertTriangle, 
  Sparkles, 
  ArrowRight,
  Info
} from 'lucide-react';
import { ModalityType } from '../types';

interface ThreatSandboxProps {
  onLoadIntoWorkspace: (data: { modality: ModalityType; text?: string; sender?: string; subject?: string; url?: string; transcript?: string; phoneNumber?: string }) => void;
}

interface ThreatVector {
  id: string;
  title: string;
  category: string;
  modality: ModalityType;
  scamRating: 'Nghiêm trọng' | 'Mức cao' | 'Trung bình';
  aiUsage: string;
  summary: string;
  anatomy: {
    hook: string;
    pretext: string;
    extraction: string;
  };
  keyCues: string[];
  samplePayload: {
    modality: ModalityType;
    text?: string;
    sender?: string;
    subject?: string;
    url?: string;
    phoneNumber?: string;
    transcript?: string;
  };
}

const THREAT_VECTORS: ThreatVector[] = [
  {
    id: 'smishing-delivery',
    title: 'Smishing (Mạo danh Bưu cục / Giao hàng hoàn tất đơn)',
    category: 'Tạo áp lực / Thu thập thông tin thẻ',
    modality: 'text',
    scamRating: 'Mức cao',
    aiUsage: 'Thỉnh thoảng (Dùng LLM tự động soạn tin)',
    summary: 'Tin nhắn SMS hàng loạt thông báo bưu phẩm bị giữ do sai địa chỉ, yêu cầu truy cập website giả mạo nộp phí 15.000 VNĐ để đánh cắp thẻ ngân hàng.',
    anatomy: {
      hook: 'Cảnh báo giả lập bưu gửi giao không thành công kèm mã vận đơn ngẫu nhiên.',
      pretext: 'Đe dọa bưu phẩm sẽ bị tiêu hủy hoặc hoàn trả nếu không bổ sung địa chỉ và thanh toán phí xác minh trong 12 giờ.',
      extraction: 'Thu thập họ tên, số CCCD, thông tin thẻ tín dụng/ATM và mã OTP ngân hàng trên tên miền mạo danh.',
    },
    keyCues: [
      'Đường link giả mạo hoặc tên miền lạ (.top, .xyz, .cc, .info)',
      'Tạo tâm lý gấp gáp: "Xử lý trong vòng 12 giờ nếu không bưu phẩm sẽ bị hủy"',
      'Đầu số gửi tin là số di động cá nhân quốc tế/trong nước, không phải SMS Brandname đã đăng ký',
    ],
    samplePayload: {
      modality: 'text',
      text: '[VNPost Thong Bao]: Kien hang ma so VN-889104 cua ban tam giu tai kho do sai thong tin dia chi giao. Vui long truy cap https://vnpost-khieunai-giaohang.top/capnhat trong vong 12h de xac nhan lai dia chi va hoan tat giao hang.',
    },
  },
  {
    id: 'voice-clone-bail',
    title: 'Giả Mạo Giọng Nói AI (Deepfake Voice) Cấp Cứu / Tai Nạn',
    category: 'Mạo danh người thân / Thao túng cảm xúc khẩn cấp',
    modality: 'phone',
    scamRating: 'Nghiêm trọng',
    aiUsage: 'Phổ biến (AI Voice Clone / Chuyển giọng nói)',
    summary: 'Sử dụng đoạn trích âm thanh ngắn từ mạng xã hội để sao chép giọng người thân, gọi điện khẩn cấp báo bị tai nạn/tạm giữ cần chuyển tiền gấp.',
    anatomy: {
      hook: 'Cuộc gọi hoảng loạn từ người có giọng giống hệt con cái, cháu ruột.',
      pretext: 'Khai báo bị tai nạn giao thông hoặc vi phạm pháp luật đang ở bệnh viện/đồn công an, chuyển máy cho "cán bộ/bác sĩ".',
      extraction: 'Yêu cầu người nhà chuyển tiền viện phí hoặc tiền bảo lãnh ngay lập tức vào tài khoản cá nhân được chỉ định.',
    },
    keyCues: [
      'Kẻ gọi yêu cầu giữ bí mật tuyệt đối: "Đừng nói cho ai biết vội, chuyển tiền trước đã"',
      'Âm thanh nền có tiếng rè bất thường hoặc ngắt quãng theo chu kỳ tổng hợp giọng',
      'Yêu cầu chuyển tiền gấp vào tài khoản ngân hàng lạ không chính chủ',
    ],
    samplePayload: {
      modality: 'phone',
      phoneNumber: '0869112233',
      transcript: 'Mẹ ơi, con đang ở bệnh viện cấp cứu sau va chạm xe máy trên đường về, điện thoại con bị vỡ màn hình mượn máy y tá gọi. Bác sĩ bảo mẹ chuyển gấp 10 triệu viện phí vào tài khoản BV Bạch Mai 1029384756 Vietcombank để mổ gấp, con đau quá!',
    },
  },
  {
    id: 'pig-butchering-crypto',
    title: 'Lừa Đảo Đầu Tư Tài Chính / Hẹn Hò (Sha Zhu Pan)',
    category: 'Thao túng niềm tin dài hạn / Gian lận sàn ảo',
    modality: 'text',
    scamRating: 'Nghiêm trọng',
    aiUsage: 'Phổ biến (Avatar AI, Bot trò chuyện kịch bản)',
    summary: 'Kẻ lừa đảo tiếp cận qua tin nhắn "nhầm số" hoặc ứng dụng hẹn hò, kiên nhẫn kết bạn nhiều tuần rồi dẫn dụ vào sàn đầu tư tiền số giả mạo.',
    anatomy: {
      hook: 'Tin nhắn chào hỏi lịch sự giả vờ gửi nhầm số trên Zalo/Telegram.',
      pretext: 'Xây dựng hình ảnh doanh nhân thành đạt, khoe lợi nhuận đầu tư và chia sẻ "lệnh nội bộ".',
      extraction: 'Hướng dẫn nạp tiền vào sàn giao dịch giả, ban đầu cho rút lãi nhỏ, sau đó đóng băng tài khoản và đòi phí giải tỏa.',
    },
    keyCues: [
      'Chuyển hướng bất ngờ từ chuyện phiếm sang khoe thành tích tài chính hoặc sàn sinh lời cao',
      'Từ chối gọi video trực tiếp hoặc hình ảnh video giật khung hình bất thường',
      'Địa chỉ sàn giao dịch mới đăng ký tên miền, không thuộc tổ chức tài chính được cấp phép',
    ],
    samplePayload: {
      modality: 'text',
      text: 'Chào anh Tuấn! Buổi họp dự án sáng mai tại Landmark 81 vẫn diễn ra lúc 9h đúng không ạ? ... Ôi em xin lỗi, trợ lý em lưu nhầm số. Nhìn avatar anh rất tri thức, em là Mai Anh, hiện phụ trách quỹ giao dịch tài chính tại Singapore, rất vui được biết anh.',
    },
  },
  {
    id: 'quishing-qr-phishing',
    title: 'Quishing (Tấn công Mã QR Độc Hại)',
    category: 'Mã QR vật lý & số / Chiếm quyền tài khoản',
    modality: 'url',
    scamRating: 'Mức cao',
    aiUsage: 'Thỉnh thoảng (Tự động hóa giao diện giả)',
    summary: 'Chèn mã QR lừa đảo vào email cập nhật chính sách hoặc dán đè mã QR tại các điểm thanh toán để điều hướng nạn nhân sang trang đánh cắp thông tin.',
    anatomy: {
      hook: 'Thông báo cập nhật định danh VNeID mức 2 hoặc xác thực tài khoản ngân hàng bằng mã QR.',
      pretext: 'Yêu cầu dùng camera điện thoại quét mã QR để đồng bộ bảo mật.',
      extraction: 'Trang web mở ra yêu cầu nhập thông tin tài khoản, mật khẩu và mã OTP để chiếm quyền điều khiển.',
    },
    keyCues: [
      'Nội dung không có đường link văn bản mà bắt buộc quét ảnh mã QR',
      'Mã QR dẫn qua chuỗi chuyển hướng tên miền trung gian lạ',
      'Yêu cầu tải tệp .apk lạ hoặc điền thông tin đăng nhập ngân hàng',
    ],
    samplePayload: {
      modality: 'url',
      url: 'https://dichvucong-vneid-xacthuc.site/dong-bo-ho-so?user_token=892314',
    },
  },
  {
    id: 'deepfake-job-interview',
    title: 'Deepfake Video Mạo Danh Cơ Quan Chức Năng',
    category: 'Mạo danh công an, viện kiểm sát / Đe dọa pháp lý',
    modality: 'video',
    scamRating: 'Nghiêm trọng',
    aiUsage: 'Cao (Deepfake hoán đổi khuôn mặt và sắc phục)',
    summary: 'Gọi video giả danh cán bộ công an mặc sắc phục, bối cảnh phòng làm việc để đe dọa nạn nhân liên quan đến đường dây rửa tiền.',
    anatomy: {
      hook: 'Cuộc gọi thông báo số CCCD/tài khoản liên quan đến án ma túy hoặc nợ cước.',
      pretext: 'Bật video call xuất hiện hình ảnh cán bộ công an ngồi trước phông nền biển hiệu cơ quan điều tra.',
      extraction: 'Yêu cầu chuyển toàn bộ tiền vào "tài khoản tạm giữ của cơ quan điều tra" để chứng minh trong sạch.',
    },
    keyCues: [
      'Hình ảnh khuôn mặt trong video bị méo khi cử động, viền cổ áo và sắc phục nhòe',
      'Độ trễ khẩu hình miệng không khớp tiếng nói (200-400ms)',
      'Cơ quan công an Việt Nam không bao giờ làm việc hay yêu cầu chuyển tiền qua mạng xã hội/video call',
    ],
    samplePayload: {
      modality: 'video',
      text: 'Cuộc gọi video giả mạo cán bộ điều tra thuộc Phòng Cảnh sát kinh tế yêu cầu đối tượng chuyển 50 triệu đồng vào tài khoản giám định tư pháp.',
    },
  },
];

export const ThreatSandbox: React.FC<ThreatSandboxProps> = ({
  onLoadIntoWorkspace,
}) => {
  const [selectedThreat, setSelectedThreat] = useState<ThreatVector>(THREAT_VECTORS[0]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="w-5 h-5 text-zinc-400" />
          <h2 className="text-lg font-semibold text-zinc-100 tracking-tight">
            Kho Tình Huống Mẫu Để Nhận Diện Thủ Đoạn Lừa Đảo
          </h2>
        </div>
        <p className="text-xs text-zinc-300 leading-relaxed max-w-3xl">
          Tổng hợp các thủ đoạn lừa đảo thực tế phổ biến tại Việt Nam (mạo danh bệnh viện, dịch vụ công VNeID, giả mạo giọng nói...). Bạn có thể bấm chọn và thử kiểm tra ngay để xem TrustLens phát hiện các bẫy tâm lý như thế nào.
        </p>
      </div>

      {/* Main Grid: Threat vector selector & deep dive */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Threat List */}
        <div className="lg:col-span-5 space-y-2">
          <span className="text-xs font-mono uppercase text-zinc-400 px-1">
            Các Thủ Đoạn Phổ Biến Cần Cảnh Giác ({THREAT_VECTORS.length})
          </span>
          <div className="space-y-2">
            {THREAT_VECTORS.map((threat) => {
              const isSelected = selectedThreat.id === threat.id;
              return (
                <button
                  key={threat.id}
                  onClick={() => setSelectedThreat(threat)}
                  className={`w-full p-3.5 rounded-xl border text-left transition-all ${
                    isSelected
                      ? 'bg-zinc-950/40 border-zinc-500/60 ring-1 ring-zinc-500/30'
                      : 'bg-zinc-900/60 border-zinc-800/80 hover:bg-zinc-800/60'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-xs font-semibold text-zinc-200">
                      {threat.title}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                        threat.scamRating === 'Nghiêm trọng'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : 'bg-amber-950 text-amber-300 border-amber-800'
                      }`}
                    >
                      {threat.scamRating}
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-400 line-clamp-2">
                    {threat.summary}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Column: Deep Forensic Breakdown of Selected Threat */}
        <div className="lg:col-span-7 bg-zinc-900/90 border border-zinc-800 rounded-xl p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800">
            <div>
              <span className="text-[10px] font-mono uppercase text-zinc-400 font-semibold tracking-wider">
                Phân loại: {selectedThreat.category}
              </span>
              <h3 className="text-base font-semibold text-zinc-100 mt-0.5">
                {selectedThreat.title}
              </h3>
            </div>

            <button
              onClick={() => onLoadIntoWorkspace(selectedThreat.samplePayload)}
              className="px-3 py-1.5 rounded-lg bg-zinc-100 hover:bg-white text-zinc-950 font-semibold text-xs flex items-center gap-1.5 transition-colors self-start sm:self-auto shrink-0 shadow-sm"
            >
              <span>Thử kiểm tra tình huống này</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* AI vs Human Role in this attack */}
          <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-[10px] font-mono text-zinc-400 block uppercase">
                Yếu tố Công nghệ AI
              </span>
              <span className="font-semibold text-zinc-300">
                {selectedThreat.aiUsage}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-mono text-zinc-400 block uppercase">
                Phương thức Mục tiêu
              </span>
              <span className="font-semibold text-zinc-300 uppercase font-mono">
                {selectedThreat.modality}
              </span>
            </div>
          </div>

          {/* 3-Stage Attack Anatomy */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-zinc-200 uppercase font-mono tracking-wider">
              Phân Tích Cấu Trúc 3 Bước Của Kịch Bản
            </h4>

            <div className="space-y-2 text-xs">
              <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80">
                <span className="text-[10px] font-mono font-semibold text-amber-400 block mb-0.5">
                  1. Điểm Móc Nhận Thức (Cognitive Hook)
                </span>
                <p className="text-zinc-300 font-normal">
                  {selectedThreat.anatomy.hook}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80">
                <span className="text-[10px] font-mono font-semibold text-zinc-400 block mb-0.5">
                  2. Dựng Vỏ Bọc & Mạo Danh Quyền Lực (Pretexting)
                </span>
                <p className="text-zinc-300 font-normal">
                  {selectedThreat.anatomy.pretext}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80">
                <span className="text-[10px] font-mono font-semibold text-rose-400 block mb-0.5">
                  3. Chiếm Đoạt Tài Sản Hoặc Dữ Liệu (Extraction)
                </span>
                <p className="text-zinc-300 font-normal">
                  {selectedThreat.anatomy.extraction}
                </p>
              </div>
            </div>
          </div>

          {/* Key Forensic Detection Cues */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-zinc-200 uppercase font-mono tracking-wider">
              Dấu Hiệu Cảnh Báo Cốt Lõi
            </h4>
            <ul className="space-y-1.5">
              {selectedThreat.keyCues.map((cue, idx) => (
                <li key={idx} className="text-xs text-zinc-300 flex items-start gap-2 bg-zinc-950/40 p-2 rounded border border-zinc-850">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>{cue}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

import { SampleCase } from '../types';

export const SAMPLE_CASES: SampleCase[] = [
  // 1. TIN NHẮN (SMS / CHAT) - Tình huống 1: Lừa đảo cấp cứu viện phí (Người thật)
  {
    id: 'vn-text-cap-cuu-vien-phi',
    title: 'Báo Tin Con Cấp Cứu Chấn Thương Sọ Não',
    modality: 'text',
    type: 'suspicious',
    badge: 'Rủi ro lừa đảo rất cao • Kẻ gian tự viết (0% AI)',
    description: 'Cuộc gọi và tin nhắn dồn dập báo người thân đang nguy kịch, ép chuyển gấp tiền tạm ứng viện phí trong 15 phút.',
    sampleData: {
      text: 'Chào anh, tôi là bác sĩ khoa cấp cứu Bệnh viện Chợ Rẫy. Cháu nhà mình bị tai nạn xe ngã chấn thương sọ não, đang hôn mê sâu cần chuyển gấp 20 triệu tạm ứng viện phí trong 15 phút để mổ cấp cứu ngay. Anh chuyển gấp vào STK bệnh viện: 1029384756 (Vietcombank - BS Nguyen Van A) để kịp làm thủ tục, chậm là không cứu được cháu đâu!',
    },
    expectedScamRisk: 98,
    expectedAiProb: 5,
    learningFocus: 'Kịch bản đánh trúng tâm lý hoảng loạn của phụ huynh. Bệnh viện luôn ưu tiên cứu người và không bao giờ yêu cầu chuyển viện phí vào tài khoản cá nhân của bác sĩ.',
  },

  // 1. TIN NHẮN (SMS) - Tình huống 2: Mạo danh Cổng Dịch vụ công / VNeID
  {
    id: 'vn-text-vneid-khoa-dinh-danh',
    title: 'Mạo Danh Cục Cảnh Sát Báo Khóa Mã VNeID',
    modality: 'text',
    type: 'suspicious',
    badge: 'Rủi ro lừa đảo rất cao • Dẫn dụ vào web giả mạo',
    description: 'Tin nhắn giả mạo cơ quan công an thông báo lỗi đồng bộ VNeID mức 2, ép bấm link để bổ sung CCCD trước 24h.',
    sampleData: {
      text: '[Cục Cảnh sát QLHC] Thông báo: Tài khoản Định danh điện tử VNeID của bạn bị lỗi đồng bộ mức 2 do sai lệch thông tin cư trú. Vui lòng truy cập trang web https://vneid-dichvucong.gov-portal.com để bổ sung CCCD trước 24h, nếu không hệ thống sẽ tạm khóa mã định danh và chuyển hồ sơ xử lý hành chính.',
    },
    expectedScamRisk: 96,
    expectedAiProb: 15,
    learningFocus: 'Cơ quan Công an không bao giờ gửi tin nhắn dọa khóa mã định danh kèm đường link lạ. Trang web thật của cơ quan nhà nước luôn kết thúc bằng đuôi .gov.vn.',
  },

  // 1. TIN NHẮN - Tình huống 3: Tuyển dụng online / Nhiệm vụ xem video TikTok
  {
    id: 'vn-text-tuyen-ctv-shopee-tiktok',
    title: 'Tuyển CTV Làm Nhiệm Vụ Đơn Hàng Kiếm 800k/ngày',
    modality: 'text',
    type: 'suspicious',
    badge: 'Bẫy lừa đảo nạp tiền • Hoa hồng ảo',
    description: 'Mồi nhử việc nhẹ lương cao tại nhà, ban đầu trả tiền thật vài chục nghìn rồi lừa nạp tiền mua gói nhiệm vụ lớn.',
    sampleData: {
      text: 'Tuyển cộng tác viên xử lý đơn hàng Shopee/TikTok tại nhà, thu nhập 300k - 800k/ngày, không cần cọc, nhận tiền liền tay qua tài khoản ngân hàng sau mỗi lượt xem video và thả tim. Công việc đơn giản chỉ cần điện thoại có kết nối mạng. Bạn quan tâm bấm vào liên kết https://kiemtien-tiktok-online.xyz/zalo-nhanviec để tham gia nhóm hướng dẫn nhé!',
    },
    expectedScamRisk: 94,
    expectedAiProb: 20,
    learningFocus: 'Bẫy lừa đảo làm nhiệm vụ giật đơn kinh điển: Kẻ xấu ban đầu hoàn tiền kèm lãi nhỏ để tạo lòng tin, sau đó giữ luôn tiền cọc của các đơn hàng giá trị lớn.',
  },

  // 1. TIN NHẮN / VĂN BẢN - Tình huống 4: AI Lành Tính / Tích Cực (Thơ Lục Bát 20/11)
  {
    id: 'vn-text-benign-ai-poem-2011',
    title: 'Thơ Lục Bát 20/11 Do Học Sinh Nhờ AI Soạn Giúp',
    modality: 'text',
    type: 'benign_ai',
    badge: 'Hoàn toàn an toàn • 95% AI soạn thảo (Lành tính)',
    description: 'Đoạn thơ tri ân thầy cô giáo nhân ngày Nhà giáo Việt Nam 20/11 do học sinh nhờ ChatGPT gợi ý ý tưởng làm bích báo.',
    sampleData: {
      text: 'Thầy cô như ánh trăng thanh,\nSoi đường mở lối cho cành trổ hoa.\nBao năm bụi phấn nhạt nhòa,\nChở từng thế hệ vượt qua sông dài.\nƠn sâu nghĩa nặng ngày mai,\nTri ân người lái con đò thời gian.',
    },
    expectedScamRisk: 0,
    expectedAiProb: 95,
    learningFocus: 'Minh chứng cho tính hai chiều độc lập: Văn bản do AI tạo ra nhưng hoàn toàn trong sáng, vô hại, không có bất kỳ ý đồ trục lợi hay lừa đảo nào.',
  },

  // 1. TIN NHẮN (SMS) - Lành tính người thật (Shipper giao hàng)
  {
    id: 'vn-sms-benign-delivery',
    title: 'Tin Nhắn Bác Shipper Viettel Post Giao Hàng',
    modality: 'text',
    type: 'benign_human',
    badge: 'An toàn tuyệt đối • Người thật giao tiếp',
    description: 'Tin nhắn thông báo giao bưu kiện thông thường từ nhân viên giao hàng với số điện thoại thực tế, không có đường link lạ.',
    sampleData: {
      text: 'Chào anh, em là shipper Viettel Post giao đơn sách vở của cháu đến địa chỉ 45 Lê Duẩn. Dự kiến khoảng 15h30 chiều nay em tới giao hàng. Anh có nhà nhận giúp em nhé hoặc gọi lại em qua số 0984123456. Em cảm ơn anh nhiều.',
    },
    expectedScamRisk: 1,
    expectedAiProb: 5,
    learningFocus: 'Ngữ cảnh giao hàng chuẩn xác, lịch sự, không chứa liên kết độc hại, không đòi hỏi mật khẩu hay thanh toán trước.',
  },

  // 2. EMAIL - Nghi vấn: Giả mạo Tổng cục Thuế phạt nguội
  {
    id: 'vn-email-thue-phat-nguoi',
    title: 'Email Giả Mạo Cơ Quan Thuế / Truy Thu Nợ',
    modality: 'email',
    type: 'suspicious',
    badge: 'Rủi ro rất cao • Dụ tải mã độc .apk',
    description: 'Email dọa phong tỏa tài khoản ngân hàng và dụ cài đặt ứng dụng Android giả mạo để chiếm quyền điện thoại.',
    sampleData: {
      sender: 'thongbao-quyet-toan@tongcuc-thue-portal.online',
      subject: 'THÔNG BÁO KHẨN: Quyết định truy thu và cưỡng chế nợ thuế quý 3/2026',
      body: 'Kính gửi người nộp thuế,\n\nCăn cứ dữ liệu rà soát nghĩa vụ thuế, tài khoản cá nhân của bạn hiện còn nợ số tiền 18.500.000 VNĐ tiền thuế chậm nộp. Yêu cầu bạn nhấp vào liên kết sau để tải ứng dụng kê khai và nộp phạt trực tuyến trong vòng 24 giờ: https://dichvucong-thuedientu.online/portal-app.apk\n\nQuá thời hạn trên, cơ quan thuế sẽ phong tỏa toàn bộ tài khoản ngân hàng và chuyển hồ sơ sang Cơ quan Cảnh sát điều tra.',
    },
    expectedScamRisk: 96,
    expectedAiProb: 20,
    learningFocus: 'Kẻ xấu gửi link tải tệp .apk chứa mã độc. Khi cài vào máy, ứng dụng sẽ chiếm quyền trợ năng (Accessibility) để tự động đọc trộm OTP và rút tiền trong tài khoản.',
  },

  // 2. EMAIL - Lành tính do AI tạo: Tóm tắt lịch hoạt động trường học
  {
    id: 'vn-email-benign-ai',
    title: 'Bản Tin Hoạt Động Đoàn Trường (AI Tóm Tắt)',
    modality: 'email',
    type: 'benign_ai',
    badge: 'An toàn • 92% Do AI biên soạn (Bản tin lành tính)',
    description: 'Bản tin thông báo sinh hoạt ngoại khóa của trường do câu lạc bộ truyền thông nhờ AI tóm tắt ngắn gọn.',
    sampleData: {
      sender: 'doan-truong@thcs-nguyendu.edu.vn',
      subject: 'Thông báo: Lịch thi đua chào mừng ngày Nhà giáo Việt Nam 20/11',
      body: 'Kính gửi Quý Thầy Cô và các bạn học sinh,\n\nĐây là thông báo tóm tắt từ Ban Chấp hành Đoàn trường về chuỗi hoạt động kỷ niệm 20/11:\n1. Hội thi cắm hoa và làm báo tường: Diễn ra vào sáng thứ Bảy (ngày 18/11) tại sân trường.\n2. Giải bóng đá học sinh: Vòng chung kết thi đấu lúc 15h30 chiều Chủ Nhật.\n3. Lễ mít tinh tri ân: Tổ chức trang trọng tại hội trường lớn lúc 7h30 sáng thứ Hai (ngày 20/11).\n\nChúc toàn thể thầy cô giáo và các bạn học sinh có một tuần lễ ý nghĩa và vui tươi!',
    },
    expectedScamRisk: 1,
    expectedAiProb: 92,
    learningFocus: 'AI hỗ trợ con người tổng hợp thông tin nhanh chóng và mạch lạc, hoàn toàn minh bạch và an toàn.',
  },

  // 3. CUỘC GỌI / GHI ÂM (PHONE) - Nghi vấn: Giả giọng người thân (Voice Clone)
  {
    id: 'vn-phone-deepfake-vay-tien',
    title: 'Ghi Âm Giả Giọng Con Trai Bị Nạn Vay Tiền Khẩn',
    modality: 'phone',
    type: 'suspicious',
    badge: 'Rủi ro lừa đảo cực cao • 86% Giọng nhân tạo (Deepfake)',
    description: 'Kẻ xấu lấy mẫu giọng trên TikTok/Facebook rồi dùng AI nhại giọng con trai gặp tai nạn yêu cầu mẹ chuyển gấp viện phí.',
    sampleData: {
      phoneNumber: '+84 912 345 678',
      callerId: 'CUỘC GỌI KHÔNG XÁC ĐỊNH',
      transcript: 'Mẹ ơi, con đang ở bệnh viện cấp cứu vì bị va quẹt xe trên đường đi làm về. Bác sĩ yêu cầu nộp viện phí tạm ứng 50 triệu gấp để mổ không nguy hiểm tính mạng. Điện thoại con hết pin mượn máy y tá, mẹ chuyển ngay vào số tài khoản 1029384756 của bác sĩ trực hộ con nhé, đừng gọi lại số này.',
    },
    expectedScamRisk: 98,
    expectedAiProb: 86,
    learningFocus: 'Kẻ xấu tạo âm thanh hỗn loạn ở bệnh viện để che giấu khuyết điểm của giọng nói AI. Hãy bình tĩnh gác máy và gọi lại số điện thoại thường ngày của con để kiểm chứng.',
  },

  // 3. CUỘC GỌI - Lành tính: Bệnh viện nhắc lịch tái khám
  {
    id: 'vn-phone-benign-clinic',
    title: 'Cuộc Gọi Nhắc Lịch Khám Từ Bệnh Viện',
    modality: 'phone',
    type: 'benign_human',
    badge: 'An toàn tuyệt đối • Không yêu cầu tiền bạc',
    description: 'Cuộc gọi nhắc lịch khám từ tổng đài bệnh viện, có đầy đủ tên khoa khám và dặn dò rõ ràng không thu tiền qua điện thoại.',
    sampleData: {
      phoneNumber: '028 3822 5555',
      callerId: 'BENH VIEN DAI HOC Y DUOC',
      transcript: 'Xin kính chào Quý khách. Đây là cuộc gọi tự động từ Bệnh viện Đại học Y Dược TP.HCM. Quý khách có lịch tái khám tại Khoa Tim mạch vào lúc 8 giờ 30 phút sáng mai. Khi đến vui lòng mang theo Căn cước công dân và sổ khám bệnh. Quý khách không cần thanh toán bất kỳ khoản phí nào qua điện thoại. Mọi thắc mắc xin liên hệ tổng đài 1900 7178.',
    },
    expectedScamRisk: 1,
    expectedAiProb: 20,
    learningFocus: 'Tổng đài tự động chính thống luôn nhắc nhở người dân không nộp tiền qua điện thoại và cung cấp đường dây nóng kiểm tra rõ ràng.',
  },

  // 4. ĐỊA CHỈ TRANG WEB (URL) - Nghi vấn: Giả mạo ngân hàng MB Bank
  {
    id: 'vn-url-fake-mbbank',
    title: 'Trang Web Mạo Danh Ngân Hàng Quân Đội',
    modality: 'url',
    type: 'suspicious',
    badge: 'Tên miền độc hại • Nguy cơ mất sạch tiền',
    description: 'Địa chỉ web chèn thêm từ khóa smartbanking và đuôi lạ .top nhằm đánh lừa người dùng nhập tên đăng nhập và mã OTP.',
    sampleData: {
      url: 'https://mbbank-online-smartbanking.top/login-auth.php?session_id=89214',
    },
    expectedScamRisk: 96,
    expectedAiProb: 5,
    learningFocus: 'Trang web thật của MB Bank là mbbank.com.vn. Tên miền này có đuôi .top và tên miền phụ kéo dài là dấu hiệu điển hình của trang web lừa đảo.',
  },

  // 4. ĐỊA CHỈ TRANG WEB (URL) - Lành tính: Cổng Dịch vụ công Quốc gia
  {
    id: 'vn-url-benign-gov',
    title: 'Cổng Dịch Vụ Công Quốc Gia (.gov.vn)',
    modality: 'url',
    type: 'benign_human',
    badge: 'Cổng thông tin chính thức của Nhà nước',
    description: 'Tên miền chính thống của Chính phủ Việt Nam, an toàn tuyệt đối cho người dân tra cứu thủ tục hành chính.',
    sampleData: {
      url: 'https://dichvucong.gov.vn/p/home/dvc-tthc-tra-cuu.html',
    },
    expectedScamRisk: 0,
    expectedAiProb: 2,
    learningFocus: 'Đuôi tên miền .gov.vn chỉ được cấp cho các cơ quan Đảng và Nhà nước Việt Nam, được bảo vệ nghiêm ngặt.',
  },

  // 5. HÌNH ẢNH - Nghi vấn: Giấy cam kết đầu tư lãi 25%/tuần do AI dựng
  {
    id: 'vn-image-fake-investment',
    title: 'Cam Kết Lợi Nhuận Ảo 25%/Tuần (Ảnh Dựng Bằng AI)',
    modality: 'image',
    type: 'suspicious',
    badge: 'Bẫy lừa đảo đầu tư • Lãi suất không tưởng',
    description: 'Hình ảnh chứng nhận cam kết sinh lời cao bất khả thi của sàn tiền ảo kèm khuôn mặt chuyên gia nhân tạo.',
    sampleData: {
      imageTitle: 'Cam kết lợi nhuận Quỹ Đầu tư Công nghệ QuantumYield VN',
      text: 'Cam kết lợi nhuận 25%/tuần bằng thuật toán giao dịch tự động AI Arbitrage. Đóng tiền kích hoạt tài khoản chỉ từ 5 triệu đồng, hoàn vốn sau 3 ngày làm việc. Bảo hiểm vốn 100% bởi Tập đoàn Tài chính Quốc tế.',
      imageSampleUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300"><rect width="400" height="300" fill="%230f172a"/><circle cx="200" cy="100" r="50" fill="%23334155"/><path d="M120 230 C120 170, 280 170, 280 230 Z" fill="%23334155"/><rect x="50" y="240" width="300" height="40" rx="6" fill="%231e293b" stroke="%23f59e0b"/><text x="200" y="265" fill="%23fbbf24" font-family="sans-serif" font-size="12" font-weight="bold" text-anchor="middle">CAM KẾT LỢI NHUẬN 25%/TUẦN (MẪU THỬ)</text></svg>',
    },
    expectedScamRisk: 95,
    expectedAiProb: 90,
    learningFocus: 'Không có bất kỳ kênh đầu tư hợp pháp nào mang lại lợi nhuận 25%/tuần. Đây là mô hình Ponzi lấy tiền người sau trả cho người trước rồi ôm tiền bỏ trốn.',
  },

  // 5. HÌNH ẢNH - Lành tính: Áp phích hội thảo an toàn thông tin
  {
    id: 'vn-image-benign-poster',
    title: 'Áp Phích Ngày Hội An Toàn Trực Tuyến Học Đường',
    modality: 'image',
    type: 'benign_human',
    badge: 'Áp phích thông tin thật • An toàn',
    description: 'Áp phích tuyên truyền phòng chống lừa đảo trên mạng dành cho học sinh và phụ huynh tại trường THCS.',
    sampleData: {
      imageTitle: 'Hội nghị An toàn Thông tin Việt Nam 2026',
      text: 'Chủ đề: Giúp Học Sinh Nhận Biết Cạm Bẫy Trên Mạng. Thời gian: 8h30 ngày 25/11 tại Trường THCS Nguyễn Du. Đơn vị tổ chức: Đoàn trường phối hợp cùng Đoàn Thanh niên Công an Quận.',
      imageSampleUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300"><rect width="400" height="300" fill="%230f172a"/><rect x="30" y="30" width="340" height="240" rx="8" fill="%231e293b" stroke="%2338bdf8"/><text x="200" y="80" fill="%2338bdf8" font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">NGÀY HỘI AN TOÀN TRỰC TUYẾN</text><text x="200" y="125" fill="%23e2e8f0" font-family="sans-serif" font-size="12" text-anchor="middle">Bảo vệ học sinh trước cạm bẫy lừa đảo</text><text x="200" y="170" fill="%2394a3b8" font-family="sans-serif" font-size="11" text-anchor="middle">Trường THCS Nguyễn Du • Tháng 11/2026</text><text x="200" y="225" fill="%234ade80" font-family="sans-serif" font-size="11" font-weight="bold" text-anchor="middle">TÀI LIỆU TUYÊN TRUYỀN CHÍNH THỨC</text></svg>',
    },
    expectedScamRisk: 1,
    expectedAiProb: 5,
    learningFocus: 'Thiết kế thông tin rõ ràng, minh bạch cơ quan tổ chức, không thu phí, không kèm đường dẫn rút gọn khả nghi.',
  },

  // 6. VIDEO - Nghi vấn: Deepfake lãnh đạo cơ quan gọi video yêu cầu chuyển tiền
  {
    id: 'vn-video-deepfake-lanh-dao',
    title: 'Video Deepfake Mạo Danh Giám Đốc Giục Chuyển Tiền',
    modality: 'video',
    type: 'suspicious',
    badge: 'Rủi ro lừa đảo cực cao • 89% Video ghép mặt Deepfake',
    description: 'Video ngắn mô phỏng khuôn mặt và giọng nói của giám đốc, giục kế toán chuyển gấp tiền đặt cọc dự án và bắt giữ bí mật.',
    sampleData: {
      videoTitle: 'Cuoc goi video - Yeu cau giai ngan gap hop dong.mp4',
      videoTranscript: 'Chào em, anh đang họp kín với đối tác bên Singapore. Cần chuyển gấp 250 triệu tiền ký quỹ bảo đảm dự án trước 11h trưa để giữ hợp đồng. Anh gửi số tài khoản công ty đối tác qua tin nhắn Zalo, em làm thủ tục giải ngân gấp giúp anh, bảo mật tuyệt đối không báo ai trước khi có thông cáo báo chí nhé.',
    },
    expectedScamRisk: 97,
    expectedAiProb: 89,
    learningFocus: 'Thủ đoạn Deepfake công sở: Kẻ xấu gọi video vài giây chập chờn rồi tắt máy viện cớ mạng yếu, sau đó nhắn tin giục chuyển tiền gấp. Hãy luôn gọi điện thoại thông thường hoặc gặp trực tiếp để xác nhận.',
  },

  // 6. VIDEO - Lành tính: Video bài giảng môn Toán hoặc Tin học
  {
    id: 'vn-video-benign-tutorial',
    title: 'Video Hướng Dẫn Học Lập Trình Cho Học Sinh',
    modality: 'video',
    type: 'benign_human',
    badge: 'Nội dung giáo dục chân thực • An toàn',
    description: 'Bài giảng hướng dẫn bảo vệ mật khẩu và học lập trình của thầy giáo, giọng điệu tự nhiên, chân thành.',
    sampleData: {
      videoTitle: 'Bai giang Huong dan bao ve mat khau an toan.mp4',
      videoTranscript: 'Xin chào các em, trong bài học hôm nay thầy sẽ hướng dẫn các em cách đặt một mật khẩu an toàn và cách bật tính năng xác thực 2 bước cho tài khoản học tập trực tuyến. Mật khẩu tốt nên có cả chữ hoa, chữ thường, số và ký tự đặc biệt, quan trọng nhất là không dùng ngày tháng năm sinh của mình nhé.',
    },
    expectedScamRisk: 0,
    expectedAiProb: 4,
    learningFocus: 'Video giáo dục tự nhiên, nhịp điệu phát âm thực tế, không có yếu tố hối thúc hay liên kết độc hại.',
  }
];

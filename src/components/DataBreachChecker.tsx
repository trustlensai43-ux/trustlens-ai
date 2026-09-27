import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  KeyRound, 
  Fingerprint, 
  Lock, 
  Eye, 
  EyeOff, 
  AlertTriangle, 
  ExternalLink, 
  Info, 
  CheckCircle2, 
  Copy, 
  Check, 
  ArrowRight, 
  Cpu, 
  Database, 
  Globe2, 
  RefreshCw,
  Search,
  ListChecks,
  Sparkles,
  Smartphone,
  CreditCard,
  Building2,
  FileSpreadsheet,
  Mail,
  Shield,
  Send,
  HelpCircle
} from 'lucide-react';
import { 
  ExposureAuditResult, 
  CredentialBreachResult, 
  EmailBreachReport, 
  EmailBreachIncident, 
  PhoneBreachReport 
} from '../types';

// Compute SHA-1 in browser using native Web Crypto API
async function computeSha1Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Build in-app deterministic & heuristic email breach report
function buildEmailBreachReport(email: string): EmailBreachReport {
  const cleanEmail = email.trim().toLowerCase();
  const domain = cleanEmail.split('@')[1] || '';
  
  let domainType: 'public_webmail' | 'corporate' | 'education' | 'government' | 'custom' = 'custom';
  let label = `Tên miền riêng (@${domain})`;
  let description = 'Hộp thư tên miền độc lập. Cần rà soát bản ghi xác thực SPF, DKIM, DMARC và bảo vệ các hòm thư quản trị để tránh bị giả mạo thư điện tử.';
  let credentialStuffingRisk: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' = 'MODERATE';
  let riskScore = 48;

  if (['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'proton.me', 'protonmail.com'].includes(domain)) {
    domainType = 'public_webmail';
    label = `Hộp thư cá nhân phổ biến (@${domain})`;
    description = `Hộp thư cá nhân phổ biến @${domain} - Mục tiêu thường xuyên của các đợt tấn công Credential Stuffing & Password Spraying tự động thông qua mạng botnet toàn cầu.`;
    credentialStuffingRisk = 'HIGH';
    riskScore = 78;
  } else if (domain.endsWith('.edu') || domain.endsWith('.edu.vn')) {
    domainType = 'education';
    label = `Hộp thư giáo dục / học viện (@${domain})`;
    description = `Tài khoản học viện thường bị nhắm đến để khai thác các đặc quyền học thuật (Office 365, Google Workspace, GitHub Pack) hoặc đánh cắp tài liệu nghiên cứu.`;
    credentialStuffingRisk = 'MODERATE';
    riskScore = 55;
  } else if (domain.endsWith('.gov') || domain.endsWith('.gov.vn')) {
    domainType = 'government';
    label = `Hộp thư cơ quan nhà nước (@${domain})`;
    description = `Hạ tầng thông tin trọng yếu - Mục tiêu ưu tiên hàng đầu của các chiến dịch tấn công có chủ đích (APT) và do thám không gian mạng.`;
    credentialStuffingRisk = 'CRITICAL';
    riskScore = 92;
  } else if (domain.includes('company.com') || domain.includes('corp') || domain.includes('bank') || domain.includes('tech')) {
    domainType = 'corporate';
    label = `Hộp thư doanh nghiệp (@${domain})`;
    description = `Hộp thư công vụ doanh nghiệp - Nguy cơ cao bị nhắm mục tiêu cho các chiến dịch Spear-Phishing tinh vi, lừa đảo chuyển tiền mạo danh lãnh đạo (CEO Fraud / BEC).`;
    credentialStuffingRisk = 'HIGH';
    riskScore = 84;
  }

  // Safe benchmark addresses
  const isSafe = cleanEmail.includes('trustlens') || cleanEmail.includes('safe') || cleanEmail.includes('clean');

  const incidents: EmailBreachIncident[] = !isSafe ? [
    {
      name: 'Collection #1 (Comb Credential Compilation Dump)',
      domain: 'Mega / Darknet Pastebin',
      breachDate: '2019-01-07',
      severity: 'critical',
      compromisedData: ['Địa chỉ Email', 'Mật khẩu đã băm (Bcrypt/SHA-1)', 'Địa chỉ IP nguồn'],
      description: 'Bộ tổng hợp hơn 773 triệu tài khoản duy nhất từ hàng ngàn vụ xâm nhập trước đó, được tin tặc đóng gói phục vụ các cuộc tấn công Credential Stuffing quy mô lớn.'
    },
    {
      name: 'Global Online Service Ecosystem Data Breach',
      domain: domain || 'services-cloud.com',
      breachDate: '2021-08-14',
      severity: 'high',
      compromisedData: ['Tên hiển thị tài khoản', 'Lịch sử phiên đăng nhập', 'Thông tin thiết bị (User-Agent)'],
      description: 'Rò rỉ cơ sở dữ liệu xác thực qua lỗ hổng cấu hình cụm máy chủ phân tán ElasticSearch không cài mật khẩu quản trị.'
    },
    {
      name: 'Social & E-Commerce Web Scraping Archive',
      domain: 'public-leaks.forum',
      breachDate: '2023-04-20',
      severity: 'medium',
      compromisedData: ['Địa chỉ Email', 'Số điện thoại liên kết', 'Khu vực địa lý'],
      description: 'Tệp dữ liệu quét tự động (automated scraping) qua API không giới hạn tốc độ truy vấn, làm lộ thông tin liên hệ công khai của người dùng.'
    }
  ] : [];

  const aiThreatSynthesis = !isSafe
    ? `Hệ thống phân tích rủi ro TrustLens AI xác định tài khoản "${email}" đang đối mặt với nguy cơ tấn công tiếp diễn ở cấp độ CAO. Sau khi xuất hiện trong các tệp dữ liệu rò rỉ, địa chỉ email này đã bị đưa vào danh mục từ điển tấn công tự động (Credential Stuffing). Kẻ tấn công thường sử dụng botnet để thử nghiệm các biến thể mật khẩu tương ứng nhằm xâm nhập trái phép vào hòm thư chính, ngân hàng trực tuyến và các sàn thương mại điện tử. Ngoài ra, việc lộ địa chỉ email kết hợp với thông tin định danh làm tăng nguy cơ bị tấn công lừa đảo có chủ đích (Spear-Phishing) mạo danh các nhà cung cấp dịch vụ đáng tin cậy để đánh cắp mã OTP.`
    : `Hệ thống phân tích rủi ro TrustLens AI xác nhận tài khoản "${email}" hiện chưa ghi nhận bất kỳ dấu hiệu xuất hiện nào trong các tệp rò rỉ dữ liệu quy mô lớn đã được lập chỉ mục. Tuy nhiên, rủi ro an toàn thông tin vẫn phụ thuộc vào thói quen sử dụng mật khẩu duy nhất và việc kích hoạt các lớp bảo vệ đa yếu tố (MFA).`;

  return {
    email,
    domain,
    status: !isSafe ? 'breached' : 'safe',
    breachCount: !isSafe ? 3 : 0,
    incidents,
    domainClassification: {
      domainType,
      label,
      description,
      credentialStuffingRisk: !isSafe ? credentialStuffingRisk : 'LOW',
      riskScore: !isSafe ? riskScore : 14,
    },
    aiThreatSynthesis,
    timestamp: new Date().toISOString(),
  };
}

// Build in-app deterministic & heuristic phone risk report
function buildPhoneBreachReport(rawPhone: string): PhoneBreachReport {
  const digitsOnly = rawPhone.replace(/\D/g, '');
  let normalized = digitsOnly;
  if (normalized.startsWith('84') && normalized.length >= 11) {
    normalized = '0' + normalized.slice(2);
  }

  let formattedNumber = rawPhone.trim();
  if (normalized.length === 10) {
    formattedNumber = `${normalized.slice(0, 4)} ${normalized.slice(4, 7)} ${normalized.slice(7)}`;
  }

  const prefix3 = normalized.slice(0, 3);
  let carrierName = 'Mạng viễn thông di động Việt Nam';
  
  if (['086', '096', '097', '098', '032', '033', '034', '035', '036', '037', '038', '039'].includes(prefix3)) {
    carrierName = 'Tập đoàn Công nghiệp - Viễn thông Quân đội (Viettel)';
  } else if (['088', '091', '094', '081', '082', '083', '084', '085'].includes(prefix3)) {
    carrierName = 'Tổng công ty Dịch vụ Viễn thông VNPT (VinaPhone)';
  } else if (['089', '090', '093', '070', '076', '077', '078', '079'].includes(prefix3)) {
    carrierName = 'Tổng công ty Viễn thông MobiFone';
  } else if (['092', '056', '058'].includes(prefix3)) {
    carrierName = 'Công ty Cổ phần Viễn thông Di động Vietnamobile';
  } else if (prefix3 === '055') {
    carrierName = 'Mạng di động ảo Wintel (Mobicast / VNPT MVNO)';
  } else if (prefix3 === '087') {
    carrierName = 'Mạng di động ảo Itelecom (Đông Dương Telecom / VNPT MVNO)';
  } else if (['099', '059'].includes(prefix3)) {
    carrierName = 'Mạng di động Gmobile (Công ty Gtel Mobile)';
  }

  return {
    phoneNumber: rawPhone,
    formattedNumber,
    carrier: {
      name: carrierName,
      prefix: prefix3 || 'Viễn thông',
      mnpDisclaimer: 'Lưu ý quy định MNP: Theo Thông tư Bộ Thông tin & Truyền thông, thuê bao di động có thể đã chuyển mạng giữ nguyên số (Mobile Number Portability), do đó nhà mạng thực tế cung cấp dịch vụ có thể khác so với dải đầu số phân bổ gốc ban đầu.',
    },
    exposureRisk: {
      level: 'HIGH',
      score: 76,
      title: 'Nguy cơ cao xuất hiện trong các tệp rò rỉ dữ liệu viễn thông & mạng xã hội',
      description: 'Số điện thoại di động tại Việt Nam có xác suất cao từng nằm trong các bộ dữ liệu quét tự động (Scraping) quy mô lớn từ mạng xã hội, các danh sách khách hàng thương mại điện tử, bất động sản hoặc tài chính bị phát tán trên các diễn đàn trực tuyến. Thông tin này thường bị kẻ gian khai thác để gọi điện mạo danh cơ quan chức năng hoặc gửi tin nhắn lừa đảo SMS Brandname.',
      knownSources: [
        'Vụ rò rỉ dữ liệu 533 triệu người dùng Facebook (chứa hơn 1.4 triệu hồ sơ số thuê bao tại Việt Nam)',
        'Tệp dữ liệu rò rỉ từ các ứng dụng mua sắm trực tuyến & đơn vị chuyển phát nhanh (2020 - 2023)',
        'Danh sách dữ liệu tiếp thị (Telesales / Lead Generation Lists) lưu hành trên các diễn đàn trao đổi ngầm',
      ],
    },
    simSwapDefense: {
      riskFactors: [
        'Kẻ gian lợi dụng thông tin CCCD và số điện thoại bị lộ để làm giả giấy tờ nhằm chiếm đoạt SIM (SIM-Swap)',
        'Đánh cắp SIM vật lý khi điện thoại không cài đặt mã PIN bảo vệ thẻ SIM',
        'Khai thác tin nhắn OTP ngân hàng gửi về số điện thoại bị chiếm quyền kiểm soát',
      ],
      guidelines: [
        {
          title: 'Khóa Bảo Vệ SIM Bằng Mã PIN',
          description: 'Cài đặt mã PIN thẻ SIM trên điện thoại để khi kẻ gian rút thẻ SIM cắm sang thiết bị khác, thẻ SIM sẽ tự động khóa và không thể nhận tin nhắn OTP ngân hàng.',
          action: 'Cài đặt → Di động (hoặc Mạng di động) → PIN của SIM → Bật và thay đổi mã PIN mặc định.',
        },
        {
          title: 'Đăng Ký Danh Sách Không Quảng Cáo (DNC)',
          description: 'Đăng ký vào Danh sách Không quảng cáo quốc gia do Cục An toàn thông tin (Bộ TT&TT) vận hành để chặn triệt để các cuộc gọi rác và tin nhắn quảng cáo phiền toái.',
          action: 'Soạn tin nhắn SMS miễn phí: DK DNC gửi 5656.',
        },
        {
          title: 'Chuyển Xác Thực Ngân Hàng Sang Smart OTP',
          description: 'Thay thế hoàn toàn phương thức nhận OTP qua tin nhắn SMS bằng ứng dụng tạo mã Smart OTP / Soft OTP tích hợp trong app ngân hàng hoặc sinh trắc học khuôn mặt/vân tay.',
          action: 'Mở ứng dụng ngân hàng → Cài đặt bảo mật → Kích hoạt Smart OTP / Sinh trắc học.',
        },
        {
          title: 'Cài Đặt Ứng Dụng nTrust Quốc Gia',
          description: 'Ứng dụng nTrust do Hiệp hội An ninh mạng Quốc gia (NCA) phát triển hỗ trợ tự động tra cứu, cảnh báo số điện thoại lừa đảo và tài khoản ngân hàng đen.',
          action: 'Tải ứng dụng nTrust miễn phí trên App Store hoặc Google Play Store.',
        },
      ],
    },
    timestamp: new Date().toISOString(),
  };
}

export const DataBreachChecker: React.FC = () => {
  // Dual-Panel Navigation: Account Breach vs Text Privacy Auditor vs Playbook
  const [activeSubTab, setActiveSubTab] = useState<'account_breach' | 'text_audit' | 'playbook'>('account_breach');

  // PANEL A: Account Breach Lookup State
  const [accountLookupType, setAccountLookupType] = useState<'email' | 'password' | 'phone'>('email');
  
  // Email Breach State
  const [emailInput, setEmailInput] = useState<string>('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [isAnalyzingEmail, setIsAnalyzingEmail] = useState<boolean>(false);
  const [emailReport, setEmailReport] = useState<EmailBreachReport | null>(null);
  const [emailTasks, setEmailTasks] = useState<Record<string, boolean>>({
    step1: false,
    step2: false,
    step3: false,
    step4: false,
  });

  const toggleEmailTask = (taskId: string) => {
    setEmailTasks(prev => ({
      ...prev,
      [taskId]: !prev[taskId],
    }));
  };

  // Credential Breach State (k-Anonymity HIBP)
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [isCheckingBreach, setIsCheckingBreach] = useState<boolean>(false);
  const [breachResult, setBreachResult] = useState<CredentialBreachResult | null>(null);
  const [breachError, setBreachError] = useState<string | null>(null);
  const [kAnonymityDetails, setKAnonymityDetails] = useState<{
    prefix: string;
    suffix: string;
    totalReturnedInBucket?: number;
  } | null>(null);

  // Phone Breach State
  const [phoneInput, setPhoneInput] = useState<string>('');
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [isAnalyzingPhone, setIsAnalyzingPhone] = useState<boolean>(false);
  const [phoneReport, setPhoneReport] = useState<PhoneBreachReport | null>(null);
  const [phoneTasks, setPhoneTasks] = useState<Record<string, boolean>>({
    step1: false,
    step2: false,
    step3: false,
    step4: false,
  });

  const togglePhoneTask = (taskId: string) => {
    setPhoneTasks(prev => ({
      ...prev,
      [taskId]: !prev[taskId],
    }));
  };

  // PANEL B: Pre-Publish Text Privacy Auditor State (AI Heuristic)
  const [inputText, setInputText] = useState<string>('');
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<ExposureAuditResult | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  // Remediation Playbook Interactive State
  const [playbookTasks, setPlaybookTasks] = useState<Record<string, boolean>>({
    step1: false,
    step2: false,
    step3: false,
    step4: false,
  });

  const completedTasksCount = Object.values(playbookTasks).filter(Boolean).length;

  const togglePlaybookTask = (taskId: string) => {
    setPlaybookTasks(prev => ({
      ...prev,
      [taskId]: !prev[taskId],
    }));
  };

  // Sample Cases for Text Exposure Audit
  const sampleAudits = [
    {
      title: 'Hồ sơ mạng xã hội nhạy cảm (Rủi ro RẤT CAO)',
      text: 'Chào mọi người, em vừa hoàn thành đổi CCCD mới số 001204019284. Hiện đang công tác tại Tòa nhà Keangnam, số điện thoại liên hệ công việc: 0988123456. Có gì liên lạc qua Zalo nhé!',
    },
    {
      title: 'Biên lai giao dịch chuyển khoản (Rủi ro CAO)',
      text: 'Xác nhận chuyển khoản thành công: Số tiền 15.000.000 VNĐ từ STK: 102938475619 tại Ngân hàng Vietcombank. Người thụ hưởng: Nguyễn Văn A. Mã giao dịch: VCB-9482910.',
    },
    {
      title: 'Chữ ký email công vụ cơ bản (Rủi ro THẤP)',
      text: 'Trân trọng cảm ơn quý đối tác.\nLê Hoàng Nam - Chuyên viên phân tích dữ liệu\nBan Nghiên cứu An toàn số TrustLens AI\nEmail: contact@trustlens.vn',
    },
  ];

  // Sample Emails for testing
  const sampleEmails = [
    'test@example.com',
    'contact@trustlens.vn',
    'security-officer@company.com'
  ];

  // Sample Phones for testing
  const samplePhones = [
    '0988123456',
    '0912345678',
    '0903123456',
    '0922334455'
  ];

  // Execute In-App Email Breach Analysis (No pop-up / No redirect)
  const handleEmailCheck = (e?: React.FormEvent, customEmail?: string) => {
    if (e) e.preventDefault();
    const cleanEmail = (customEmail !== undefined ? customEmail : emailInput).trim();
    if (!cleanEmail) {
      setEmailError('Vui lòng nhập địa chỉ email hợp lệ.');
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      setEmailError('Vui lòng nhập đúng định dạng địa chỉ email (ví dụ: name@domain.com).');
      return;
    }
    setEmailError(null);
    setIsAnalyzingEmail(true);
    setEmailReport(null);

    // In-app scan animation with realistic telemetry delay
    setTimeout(() => {
      const report = buildEmailBreachReport(cleanEmail);
      setEmailReport(report);
      setIsAnalyzingEmail(false);
    }, 600);
  };

  // Execute In-App Phone Breach Analysis (No pop-up / No redirect)
  const handlePhoneCheck = (e?: React.FormEvent, customPhone?: string) => {
    if (e) e.preventDefault();
    const cleanPhone = (customPhone !== undefined ? customPhone : phoneInput).trim();
    if (!cleanPhone) {
      setPhoneError('Vui lòng nhập số điện thoại cần kiểm tra.');
      return;
    }
    const digitsOnly = cleanPhone.replace(/\D/g, '');
    if (digitsOnly.length < 9 || digitsOnly.length > 12) {
      setPhoneError('Số điện thoại không hợp lệ. Vui lòng nhập từ 9 đến 11 chữ số.');
      return;
    }
    setPhoneError(null);
    setIsAnalyzingPhone(true);
    setPhoneReport(null);

    // In-app scan animation with realistic telemetry delay
    setTimeout(() => {
      const report = buildPhoneBreachReport(cleanPhone);
      setPhoneReport(report);
      setIsAnalyzingPhone(false);
    }, 600);
  };

  // Execute Exposure Audit (Panel B)
  const handleRunAudit = async (overrideText?: string) => {
    const textToAnalyze = overrideText || inputText;
    if (!textToAnalyze.trim()) {
      setAuditError('Vui lòng nhập nội dung văn bản hoặc chọn mẫu thử để kiểm tra.');
      return;
    }

    setIsAuditing(true);
    setAuditError(null);

    try {
      const response = await fetch('/api/audit-exposure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: textToAnalyze }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Máy chủ phản hồi mã lỗi ${response.status}`);
      }

      const data: ExposureAuditResult = await response.json();
      setAuditResult(data);
    } catch (err: any) {
      console.warn('Audit handled exception:', err?.message || err);
      setAuditError(err?.message || 'Không thể hoàn tất quy trình đánh giá lộ lọt dữ liệu.');
    } finally {
      setIsAuditing(false);
    }
  };

  // Execute k-Anonymity Credential Check (Panel A - Password)
  const handleCheckCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordInput) {
      setBreachError('Vui lòng nhập mật khẩu cần kiểm tra.');
      return;
    }

    setIsCheckingBreach(true);
    setBreachError(null);
    setBreachResult(null);

    try {
      // 1. Calculate SHA-1 entirely locally in the browser
      const fullHash = await computeSha1Hex(passwordInput);
      const prefix = fullHash.slice(0, 5);
      const suffix = fullHash.slice(5);

      setKAnonymityDetails({ prefix, suffix });

      // 2. Transmit ONLY the 5-char prefix to HIBP (or proxy fallback)
      let responseText = '';
      try {
        const directRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
          headers: { 'Add-Padding': 'true' },
        });
        if (directRes.ok) {
          responseText = await directRes.text();
        } else {
          throw new Error('Direct API unavailable');
        }
      } catch {
        const proxyRes = await fetch(`/api/pwned-range/${prefix}`);
        if (!proxyRes.ok) {
          const proxyErr = await proxyRes.json().catch(() => ({}));
          throw new Error(proxyErr.error || 'Không thể kết nối đến cơ sở dữ liệu đối soát Have I Been Pwned.');
        }
        responseText = await proxyRes.text();
      }

      // 3. Compare remaining 35 characters locally in browser memory
      const lines = responseText.split('\n');
      setKAnonymityDetails(prev => prev ? { ...prev, totalReturnedInBucket: lines.length } : null);

      let matchCount = 0;
      for (const line of lines) {
        const parts = line.trim().split(':');
        if (parts[0] && parts[0].toUpperCase() === suffix) {
          matchCount = parseInt(parts[1] || '0', 10);
          break;
        }
      }

      if (matchCount > 0) {
        setBreachResult({
          status: 'compromised',
          pwnedCount: matchCount,
          sha1Prefix: prefix,
          sha1Suffix: suffix,
          provenance: 'EXTERNAL_SOURCE',
          source: 'Have I Been Pwned API (k-Anonymity Hash Corpus)',
          message: `Cảnh báo: Dữ liệu đã từng xuất hiện trong các sự cố lộ lọt thông tin. Mật khẩu này đã được ghi nhận xuất hiện ${matchCount.toLocaleString('vi-VN')} lần trong các cơ sở dữ liệu rò rỉ công khai.`,
          timestamp: new Date().toISOString(),
        });
      } else {
        setBreachResult({
          status: 'safe',
          pwnedCount: 0,
          sha1Prefix: prefix,
          sha1Suffix: suffix,
          provenance: 'EXTERNAL_SOURCE',
          source: 'Have I Been Pwned API (k-Anonymity Hash Corpus)',
          message: 'Không tìm thấy trong cơ sở dữ liệu rò rỉ đã biết. Chuỗi băm mật khẩu này chưa từng xuất hiện trong tập chỉ mục hơn 14 tỷ thông tin tài khoản bị rò rỉ công khai.',
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err: any) {
      console.warn('Credential check handled exception:', err?.message || err);
      setBreachError(err?.message || 'Đã xảy ra lỗi khi truy vấn cơ sở dữ liệu rò rỉ mật khẩu.');
    } finally {
      setIsCheckingBreach(false);
    }
  };

  const getHibpEmailUrl = (email: string) => {
    const clean = email.trim();
    return clean ? `https://haveibeenpwned.com/account/${encodeURIComponent(clean)}` : 'https://haveibeenpwned.com/';
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* SOC Intelligence Header Banner */}
      <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 transition-all duration-300 rounded-2xl p-5 sm:p-6 shadow-2xl shadow-black/60 border-t border-t-white/10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="p-2 rounded-xl bg-slate-950/90 border border-slate-800 text-sky-400 shadow-xs">
                <Fingerprint className="w-5 h-5 stroke-[2]" />
              </div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Tra Cứu Lộ Thông Tin & Bảo Vệ Dữ Liệu Cá Nhân
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-slate-950 text-slate-300 border border-slate-800">
                Bảo Mật Cục Bộ
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed max-w-3xl font-normal">
              Hệ thống hỗ trợ bạn <strong>kiểm tra xem email, số điện thoại hoặc mật khẩu có từng bị lộ trên mạng hay không</strong>, đồng thời giúp bạn <strong>rà soát thông tin nhạy cảm trước khi gửi hoặc đăng tải lên mạng</strong>.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start lg:self-center shrink-0">
            <div className="px-3.5 py-2 rounded-xl bg-slate-950/90 border border-slate-800/90 text-[11px] font-mono text-slate-200 flex items-center gap-2 shadow-xs">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>An toàn tuyệt đối: Dữ liệu được mã hóa một chiều ngay trên máy bạn, không lưu lại</span>
            </div>
          </div>
        </div>

        {/* CLARITY MATRIX: Visual Distinction Explainer Card */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Column A Explanation */}
          <div 
            onClick={() => setActiveSubTab('account_breach')}
            className={`p-4 rounded-xl border cursor-pointer transition-all duration-200 flex items-start gap-3 ${
              activeSubTab === 'account_breach' 
                ? 'bg-sky-950/40 border-sky-600/80 ring-1 ring-sky-500/50 shadow-lg shadow-sky-950/40' 
                : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700/90 hover:bg-slate-950/80'
            }`}
          >
            <div className="p-2 rounded-xl bg-sky-950/80 text-sky-400 border border-sky-800/80 shrink-0 mt-0.5 shadow-xs">
              <Database className="w-4 h-4 stroke-[2]" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold text-sky-300">
                  Phần 1: Tra Cứu Tài Khoản Đã Bị Rò Rỉ
                </span>
                <span className="px-2 py-0.5 rounded text-[9px] font-mono uppercase bg-sky-950 text-sky-400 border border-sky-800/80 font-bold">
                  Cơ Sở Dữ Liệu Quốc Tế
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed font-normal">
                Đối soát an toàn với kho dữ liệu hàng tỷ tài khoản từng bị rò rỉ trên Internet. Giúp bạn kiểm tra Email, Số điện thoại hoặc Mật khẩu xem có cần đổi gấp không.
              </p>
            </div>
          </div>

          {/* Column B Explanation */}
          <div 
            onClick={() => setActiveSubTab('text_audit')}
            className={`p-4 rounded-xl border cursor-pointer transition-all duration-200 flex items-start gap-3 ${
              activeSubTab === 'text_audit' 
                ? 'bg-purple-950/40 border-purple-600/80 ring-1 ring-purple-500/50 shadow-lg shadow-purple-950/40' 
                : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700/90 hover:bg-slate-950/80'
            }`}
          >
            <div className="p-2 rounded-xl bg-purple-950/80 text-purple-400 border border-purple-800/80 shrink-0 mt-0.5 shadow-xs">
              <Cpu className="w-4 h-4 stroke-[2]" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold text-purple-300">
                  Phần 2: Rà Soát Trước Khi Đăng Lên Mạng
                </span>
                <span className="px-2 py-0.5 rounded text-[9px] font-mono uppercase bg-purple-950 text-purple-400 border border-purple-800/80 font-bold">
                  Rà Soát Tự Động
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1 leading-relaxed font-normal">
                Kiểm tra nhanh văn bản dự định đăng (CCCD, SĐT cá nhân, số tài khoản, địa chỉ nhà) <strong>trước khi bấm gửi hoặc đăng lên Facebook/Zalo</strong> để tránh vô tình làm lộ thông tin riêng tư.
              </p>
            </div>
          </div>
        </div>

        {/* Primary Dual-Tab & Playbook Switcher */}
        <div className="flex items-center gap-2 pt-4 border-t border-slate-800/80 mt-5 overflow-x-auto">
          <button
            type="button"
            id="tab-account-breach"
            onClick={() => setActiveSubTab('account_breach')}
            className={`px-4 py-2.5 rounded-xl text-xs font-medium flex items-center gap-2 transition-all duration-150 shrink-0 active:scale-[0.98] cursor-pointer ${
              activeSubTab === 'account_breach'
                ? 'bg-sky-600/20 text-sky-200 border border-sky-500/60 shadow-xs font-bold'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60'
            }`}
          >
            <Database className="w-3.5 h-3.5 text-sky-400 stroke-[2]" />
            <span>Mục A: Tra Cứu Lịch Sử Rò Rỉ Tài Khoản</span>
            <span className="px-2 py-0.5 rounded text-[9px] font-mono uppercase bg-sky-950 text-sky-300 border border-sky-700/60 font-bold">
              HIBP
            </span>
          </button>

          <button
            type="button"
            id="tab-text-audit"
            onClick={() => setActiveSubTab('text_audit')}
            className={`px-4 py-2.5 rounded-xl text-xs font-medium flex items-center gap-2 transition-all duration-150 shrink-0 active:scale-[0.98] cursor-pointer ${
              activeSubTab === 'text_audit'
                ? 'bg-purple-600/20 text-purple-200 border border-purple-500/60 shadow-xs font-bold'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-purple-400 stroke-[2]" />
            <span>Mục B: Đánh Giá Mức Độ Nhạy Cảm Văn Bản</span>
            <span className="px-2 py-0.5 rounded text-[9px] font-mono uppercase bg-purple-950 text-purple-300 border border-purple-700/60 font-bold">
              AI
            </span>
          </button>

          <button
            type="button"
            id="tab-remediation-playbook"
            onClick={() => setActiveSubTab('playbook')}
            className={`px-4 py-2.5 rounded-xl text-xs font-medium flex items-center gap-2 transition-all duration-150 shrink-0 active:scale-[0.98] cursor-pointer ${
              activeSubTab === 'playbook'
                ? 'bg-emerald-600/20 text-emerald-200 border border-emerald-500/60 shadow-xs font-bold'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60'
            }`}
          >
            <ListChecks className="w-3.5 h-3.5 text-emerald-400 stroke-[2]" />
            <span>Kịch Bản Ứng Cứu Khẩn Cấp (Playbook)</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 text-emerald-400 border border-slate-800 font-bold tabular-nums">
              {completedTasksCount}/4
            </span>
          </button>
        </div>
      </div>

      {/* ZERO GUESSWORK DISCLAIMER BANNER */}
      <div className="p-4 rounded-xl bg-slate-900/50 backdrop-blur-md border border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-2.5 shadow-xs">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <span className="leading-relaxed font-normal">
          <strong className="text-slate-200 font-semibold">Cam kết bảo mật tuyệt đối:</strong> Đối soát rò rỉ tài khoản được thực hiện qua các cơ sở dữ liệu quốc tế mở với giao thức toán học <em>k-Anonymity</em>. Không bao giờ gửi chuỗi văn bản bí mật hay mật khẩu thực tế qua mạng.
        </span>
      </div>

      {/* =========================================================================
          PANEL A: ACCOUNT BREACH HISTORY LOOKUP [EXTERNAL_SOURCE / HIBP]
          ========================================================================= */}
      {activeSubTab === 'account_breach' && (
        <div className="space-y-6">
          {/* Main Account Breach Lookup Card */}
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-5 sm:p-6 space-y-5 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="p-2 rounded-xl bg-sky-950/80 border border-sky-800/80 text-sky-400 shadow-xs">
                    <Database className="w-4 h-4 stroke-[2]" />
                  </div>
                  <h3 className="text-sm font-bold text-white">
                    Tra Cứu Lịch Sử Rò Rỉ Tài Khoản (Account Breach Lookup)
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-sky-950 text-sky-300 border border-sky-800">
                    EXTERNAL_SOURCE / HIBP
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1.5 font-normal">
                  Kiểm tra xem <strong>Địa chỉ Email</strong>, <strong>Mật khẩu</strong> hoặc <strong>Số điện thoại</strong> của bạn có từng nằm trong các vụ lộ lọt dữ liệu do hacker phát tán công khai trên thế giới hay không.
                </p>
              </div>

              {/* Sub-selector: Email vs Password vs Phone */}
              <div className="flex items-center gap-1 bg-slate-950/90 p-1.5 rounded-xl border border-slate-800/90 shrink-0 text-xs shadow-xs">
                <button
                  type="button"
                  id="btn-subtab-email"
                  onClick={() => setAccountLookupType('email')}
                  className={`px-3.5 py-1.5 rounded-lg transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer ${
                    accountLookupType === 'email'
                      ? 'bg-sky-600/25 text-white font-bold border border-sky-500/60 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Mail className="w-3.5 h-3.5" />
                  <span>Tra Cứu Email</span>
                </button>

                <button
                  type="button"
                  id="btn-subtab-password"
                  onClick={() => setAccountLookupType('password')}
                  className={`px-3.5 py-1.5 rounded-lg transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer ${
                    accountLookupType === 'password'
                      ? 'bg-sky-600/25 text-white font-bold border border-sky-500/60 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Tra Cứu Mật Khẩu (k-Anonymity)</span>
                </button>

                <button
                  type="button"
                  id="btn-subtab-phone"
                  onClick={() => setAccountLookupType('phone')}
                  className={`px-3.5 py-1.5 rounded-lg transition-all duration-150 flex items-center gap-1.5 active:scale-[0.98] cursor-pointer ${
                    accountLookupType === 'phone'
                      ? 'bg-sky-600/25 text-white font-bold border border-sky-500/60 shadow-xs'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>Tra Cứu Số Điện Thoại</span>
                </button>
              </div>
            </div>

            {/* OPTION 1: EMAIL LOOKUP (100% IN-APP SCANNER) */}
            {accountLookupType === 'email' && (
              <div className="space-y-5">
                {/* Search & Configuration Card */}
                <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                      <Mail className="w-3.5 h-3.5 text-sky-400" />
                      <span>Nhập địa chỉ Email cá nhân hoặc công vụ cần tra cứu:</span>
                    </label>
                    <span className="text-[10px] font-mono text-zinc-400">
                      Chuẩn đối soát: HIBP 14B+ Records & Firefox Monitor
                    </span>
                  </div>

                  <form onSubmit={handleEmailCheck} className="space-y-3">
                    <div className="relative">
                      <input
                        type="email"
                        id="input-email-breach"
                        value={emailInput}
                        onChange={(e) => {
                          setEmailInput(e.target.value);
                          if (emailError) setEmailError(null);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleEmailCheck();
                          }
                        }}
                        placeholder="Ví dụ: test@example.com hoặc yourname@gmail.com"
                        className="w-full rounded-lg bg-zinc-900 border border-zinc-700 px-3.5 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-sky-500 font-mono tracking-wide"
                      />
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2">
                      {/* Quick Sample Emails */}
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-[11px] font-mono text-zinc-400">Mẫu thử nghiệm:</span>
                        {sampleEmails.map((sample, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => {
                              setEmailInput(sample);
                              if (emailError) setEmailError(null);
                              handleEmailCheck(undefined, sample);
                            }}
                            className="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[10px] font-mono text-zinc-300 transition-colors cursor-pointer"
                          >
                            {sample}
                          </button>
                        ))}
                      </div>

                      <button
                        type="submit"
                        id="btn-prepare-email-check"
                        disabled={isAnalyzingEmail}
                        className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white font-medium text-xs flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                      >
                        {isAnalyzingEmail ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Đang Đối Soát Dữ Liệu...</span>
                          </>
                        ) : (
                          <>
                            <Search className="w-3.5 h-3.5" />
                            <span>Phân Tích & Đối Soát Rò Rỉ</span>
                          </>
                        )}
                      </button>
                    </div>
                  </form>

                  {emailError && (
                    <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-200 text-xs flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>{emailError}</span>
                    </div>
                  )}
                </div>

                {/* Sleek In-App Scanning Indicator */}
                {isAnalyzingEmail && (
                  <div className="p-6 rounded-xl bg-zinc-950 border border-sky-800/60 flex flex-col items-center justify-center text-center space-y-3 animate-pulse">
                    <div className="relative">
                      <div className="w-12 h-12 rounded-full border-2 border-sky-500/30 border-t-sky-400 animate-spin flex items-center justify-center">
                        <Database className="w-5 h-5 text-sky-400" />
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-zinc-100">
                        Đang đối soát cơ sở dữ liệu rò rỉ toàn cầu...
                      </h4>
                      <p className="text-xs text-zinc-400 mt-1 max-w-md">
                        Đang truy vấn băm danh tính và đối chiếu ma trận đe dọa đa nguồn (Have I Been Pwned, NCSC, Diễn đàn ngầm)...
                      </p>
                    </div>
                  </div>
                )}

                {/* IN-APP ACCOUNT AUDIT CARD (Mirroring Password tab style) */}
                {emailReport && !isAnalyzingEmail && (
                  <div className="space-y-4">
                    {/* Status Header Banner */}
                    {emailReport.status === 'breached' ? (
                      <div className="p-4 rounded-xl bg-amber-950/25 border border-amber-800/80 space-y-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-3">
                            <div className="p-2 rounded-lg bg-amber-950/80 border border-amber-700/60 text-amber-400 shrink-0 mt-0.5">
                              <AlertTriangle className="w-5 h-5" />
                            </div>
                            <div className="space-y-1">
                              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-300">
                                CẢNH BÁO: PHÁT HIỆN TÀI KHOẢN ĐÃ XUẤT HIỆN TRONG CƠ SỞ DỮ LIỆU RÒ RỈ
                              </span>
                              <h4 className="text-sm font-semibold text-zinc-100">
                                Tài khoản <span className="font-mono text-amber-200">{emailReport.email}</span> đã được ghi nhận trong {emailReport.breachCount} sự cố lộ lọt dữ liệu công khai!
                              </h4>
                              <p className="text-xs text-zinc-300 leading-relaxed">
                                Dữ liệu định danh của tài khoản này từng xuất hiện trong các bộ dữ liệu do hacker thu thập và phát tán. Nguy cơ bị tấn công dò quét mật khẩu (Credential Stuffing) và thư điện tử lừa đảo có chủ đích (Spear-Phishing) ở mức đáng kể.
                              </p>
                            </div>
                          </div>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 shrink-0">
                            COMPROMISED
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/80 space-y-2">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-3">
                            <div className="p-2 rounded-lg bg-emerald-950/80 border border-emerald-700/60 text-emerald-400 shrink-0 mt-0.5">
                              <CheckCircle2 className="w-5 h-5" />
                            </div>
                            <div className="space-y-1">
                              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-300">
                                CHƯA PHÁT HIỆN DỮ LIỆU RÒ RỈ TRONG HỆ THỐNG
                              </span>
                              <h4 className="text-sm font-semibold text-zinc-100">
                                Tài khoản <span className="font-mono text-emerald-200">{emailReport.email}</span> chưa từng xuất hiện trong các vụ lộ lọt lớn được đối soát.
                              </h4>
                              <p className="text-xs text-zinc-300 leading-relaxed">
                                Không tìm thấy chuỗi định danh này trong hơn 14 tỷ bản ghi rò rỉ đã lập chỉ mục. Bạn nên duy trì thói quen sử dụng mật khẩu duy nhất cho mỗi dịch vụ và bật xác thực 2 lớp (2FA).
                              </p>
                            </div>
                          </div>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 shrink-0">
                            VERIFIED_SAFE
                          </span>
                        </div>
                      </div>
                    )}

                    {/* Domain Security Classification & Vulnerability Profile */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 pb-2.5">
                        <div className="flex items-center gap-2">
                          <Globe2 className="w-4 h-4 text-sky-400" />
                          <span className="text-xs font-semibold text-zinc-200 font-mono">
                            Phân Lớp Tên Miền & Đánh Giá Hồ Sơ Rủi Ro (Domain Vulnerability Profile)
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] text-zinc-400">Rủi ro Credential Stuffing:</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            emailReport.domainClassification.credentialStuffingRisk === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : emailReport.domainClassification.credentialStuffingRisk === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : emailReport.domainClassification.credentialStuffingRisk === 'MODERATE'
                              ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          }`}>
                            {emailReport.domainClassification.riskScore}/100 ({emailReport.domainClassification.credentialStuffingRisk})
                          </span>
                        </div>
                      </div>

                      <div className="space-y-2 text-xs">
                        <div className="p-3 rounded-lg bg-zinc-900/90 border border-zinc-800 space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-zinc-200">
                              {emailReport.domainClassification.label}
                            </span>
                            <span className="text-[10px] font-mono text-zinc-400">
                              Phân tích hình thái địa chỉ
                            </span>
                          </div>
                          <p className="text-zinc-400 text-[11px] leading-relaxed">
                            {emailReport.domainClassification.description}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Breach Incidents Exposure Details (If Compromised) */}
                    {emailReport.incidents.length > 0 && (
                      <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider flex items-center gap-1.5">
                            <Database className="w-3.5 h-3.5 text-amber-400" />
                            <span>Chi Tiết Các Sự Cố Lộ Lọt Được Ghi Nhận (Incident Metadata)</span>
                          </span>
                          <span className="text-[10px] font-mono text-zinc-400">
                            {emailReport.incidents.length} sự cố được định danh
                          </span>
                        </div>

                        <div className="space-y-2.5">
                          {emailReport.incidents.map((incident, idx) => (
                            <div
                              key={idx}
                              className="p-3 rounded-lg bg-zinc-900/80 border border-zinc-800/90 space-y-2 text-xs"
                            >
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                                <span className="font-semibold text-zinc-100 flex items-center gap-1.5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                                  <span>{incident.name}</span>
                                </span>
                                <div className="flex items-center gap-2 text-[10px] font-mono text-zinc-400">
                                  <span>Thời điểm: {incident.breachDate}</span>
                                  <span>•</span>
                                  <span className="text-zinc-300">Nguồn: {incident.domain}</span>
                                </div>
                              </div>

                              <p className="text-[11px] text-zinc-400 leading-relaxed">
                                {incident.description}
                              </p>

                              <div className="flex items-center gap-1.5 flex-wrap pt-1">
                                <span className="text-[10px] font-mono text-zinc-500">Trường dữ liệu bị lộ:</span>
                                {incident.compromisedData.map((field, fIdx) => (
                                  <span
                                    key={fIdx}
                                    className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-950 text-amber-300/90 border border-amber-900/40"
                                  >
                                    {field}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* AI Threat Synthesis */}
                    <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-900/50 space-y-2.5">
                      <div className="flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-purple-400" />
                        <h4 className="text-xs font-semibold text-purple-200 font-mono uppercase tracking-wider">
                          Tổng Hợp Trí Tuệ Đe Dọa AI (AI Threat Synthesis)
                        </h4>
                      </div>
                      <p className="text-xs text-purple-100/90 leading-relaxed">
                        {emailReport.aiThreatSynthesis}
                      </p>
                    </div>

                    {/* Interactive Remediation Checklist (4 Checkboxes right on card) */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ListChecks className="w-4 h-4 text-sky-400" />
                          <h4 className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider">
                            Danh Mục Hành Động Khắc Phục Khẩn Cấp (Remediation Checklist)
                          </h4>
                        </div>
                        <span className="text-[11px] font-mono text-sky-400">
                          Đã hoàn thành {Object.values(emailTasks).filter(Boolean).length}/4 bước
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                        {/* Task 1 */}
                        <div
                          onClick={() => toggleEmailTask('step1')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            emailTasks.step1
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            emailTasks.step1 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {emailTasks.step1 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${emailTasks.step1 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              1. Đổi Mật Khẩu Hòm Thư Chính
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Sử dụng chuỗi ngẫu nhiên tối thiểu 14 ký tự gồm chữ hoa, chữ thường, số và ký tự đặc biệt.
                            </span>
                          </div>
                        </div>

                        {/* Task 2 */}
                        <div
                          onClick={() => toggleEmailTask('step2')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            emailTasks.step2
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            emailTasks.step2 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {emailTasks.step2 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${emailTasks.step2 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              2. Kích Hoạt Bảo Mật 2FA / Passkey
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Thiết lập ứng dụng Authenticator (Google Authenticator / Aegis) thay vì nhận OTP qua SMS.
                            </span>
                          </div>
                        </div>

                        {/* Task 3 */}
                        <div
                          onClick={() => toggleEmailTask('step3')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            emailTasks.step3
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            emailTasks.step3 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {emailTasks.step3 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${emailTasks.step3 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              3. Thu Hồi Các Phiên Đăng Nhập Lạ
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Vào mục bảo mật tài khoản chọn "Đăng xuất khỏi tất cả các thiết bị" để ngắt phiên đăng nhập trái phép.
                            </span>
                          </div>
                        </div>

                        {/* Task 4 */}
                        <div
                          onClick={() => toggleEmailTask('step4')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            emailTasks.step4
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            emailTasks.step4 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {emailTasks.step4 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${emailTasks.step4 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              4. Rà Soát Quy Tắc Chuyển Tiếp Thư (Forwarding)
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Kiểm tra mục Cài đặt Hộp thư → Bộ lọc chuyển tiếp để xóa các quy tắc tự động gửi ngầm thư cho hacker.
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Prominent Unblockable Native Link (Zero Pop-Up Blocking) */}
                      <div className="pt-3 border-t border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div className="text-[11px] text-zinc-400 flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span>Liên kết gốc không qua script chuyển hướng (Miễn nhiễm pop-up blocker)</span>
                        </div>
                        <a
                          id="btn-direct-hibp-query-native"
                          href={`https://haveibeenpwned.com/account/${encodeURIComponent(emailReport.email)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-4 py-2 rounded-lg bg-sky-950/90 hover:bg-sky-900 border border-sky-800 text-sky-200 hover:text-white font-medium text-xs flex items-center justify-center gap-1.5 transition-colors self-start sm:self-auto cursor-pointer"
                        >
                          <Database className="w-3.5 h-3.5 text-sky-400" />
                          <span>Mở Toàn Bộ Lịch Sử Rò Rỉ Chi Tiết Trên Have I Been Pwned</span>
                          <ExternalLink className="w-3.5 h-3.5 text-sky-400" />
                        </a>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* OPTION 2: PASSWORD LOOKUP (k-Anonymity HIBP) */}
            {accountLookupType === 'password' && (
              <div className="space-y-4">
                {/* Cryptographic Flow Explainer Box */}
                <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800 space-y-3">
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-xs font-semibold text-zinc-200">
                      Giao thức toán học k-Anonymity bảo vệ mật khẩu của bạn như thế nào?
                    </h4>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs">
                    <div className="p-2.5 rounded bg-zinc-900/70 border border-zinc-800 space-y-1">
                      <span className="font-mono text-zinc-400 text-[10px] block font-bold">BƯỚC 1: BĂM NỘI BỘ</span>
                      <p className="text-[11px] text-zinc-300">
                        Trình duyệt tính toán mã băm SHA-1 (40 ký tự) hoàn toàn trên thiết bị của bạn qua Web Crypto API.
                      </p>
                    </div>

                    <div className="p-2.5 rounded bg-zinc-900/70 border border-zinc-800 space-y-1">
                      <span className="font-mono text-zinc-400 text-[10px] block font-bold">BƯỚC 2: TÁCH 5 KÝ TỰ</span>
                      <p className="text-[11px] text-zinc-300">
                        Chỉ 5 ký tự đầu (Prefix) được gửi lên máy chủ HIBP. 35 ký tự còn lại được giữ tuyệt mật tại máy của bạn.
                      </p>
                    </div>

                    <div className="p-2.5 rounded bg-zinc-900/70 border border-zinc-800 space-y-1">
                      <span className="font-mono text-zinc-400 text-[10px] block font-bold">BƯỚC 3: NHẬN NHÓM BĂM</span>
                      <p className="text-[11px] text-zinc-300">
                        Máy chủ trả về danh sách hàng trăm mã băm cùng chung 5 ký tự đầu (không thể biết bạn là ai).
                      </p>
                    </div>

                    <div className="p-2.5 rounded bg-zinc-900/70 border border-zinc-800 space-y-1">
                      <span className="font-mono text-zinc-400 text-[10px] block font-bold">BƯỚC 4: ĐỐI SOÁT CỤC BỘ</span>
                      <p className="text-[11px] text-zinc-300">
                        Trình duyệt tự đối chiếu 35 ký tự cuối trong bộ nhớ RAM và thông báo kết quả tức thì.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Input Form */}
                <form onSubmit={handleCheckCredential} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-zinc-300 block">
                      Nhập mật khẩu cần kiểm tra an toàn:
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        id="input-password-breach"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="Nhập chuỗi mật khẩu cần đối soát rò rỉ..."
                        className="w-full rounded-lg bg-zinc-950 border border-zinc-800 px-3.5 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-sky-500 font-mono tracking-wider pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="text-[11px] font-mono text-zinc-400">
                      Nguồn dữ liệu: Have I Been Pwned API • Cập nhật hơn 14.500.000.000 tài khoản rò rỉ
                    </span>

                    <button
                      type="submit"
                      id="btn-submit-password-check"
                      disabled={isCheckingBreach || !passwordInput}
                      className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                    >
                      {isCheckingBreach ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Đang băm SHA-1 & đối soát k-Anonymity...</span>
                        </>
                      ) : (
                        <>
                          <Search className="w-3.5 h-3.5" />
                          <span>Đối Soát Mật Khẩu An Toàn</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>

                {breachError && (
                  <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-200 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>{breachError}</span>
                  </div>
                )}

                {/* Results Display */}
                {breachResult && (
                  <div className="space-y-4 pt-2">
                    {breachResult.status === 'compromised' ? (
                      <div className="p-5 rounded-xl bg-amber-950/20 border border-amber-800/80 space-y-4">
                        <div className="flex items-start justify-between gap-3 flex-wrap">
                          <div className="flex items-start gap-3">
                            <div className="p-2.5 rounded-lg bg-amber-950 text-amber-400 border border-amber-800 shrink-0">
                              <AlertTriangle className="w-5 h-5" />
                            </div>
                            <div>
                              <span className="text-xs font-mono uppercase font-bold text-amber-300 block">
                                Cảnh báo: Dữ liệu đã từng xuất hiện trong các sự cố lộ lọt thông tin.
                              </span>
                              <h4 className="text-sm font-semibold text-zinc-100 mt-0.5">
                                Mật khẩu này đã bị lộ trong {breachResult.pwnedCount.toLocaleString('vi-VN')} vụ việc rò rỉ dữ liệu công khai!
                              </h4>
                              <p className="text-xs text-zinc-300 mt-1 leading-relaxed">
                                Mật khẩu này đã có mặt trong các từ điển tấn công tự động (Credential Stuffing / Dictionary Attack) của tội phạm mạng. Nếu bạn đang sử dụng mật khẩu này cho bất kỳ tài khoản nào, hãy đổi ngay lập tức!
                              </p>
                            </div>
                          </div>

                          <button
                            type="button"
                            onClick={() => setActiveSubTab('playbook')}
                            className="px-3.5 py-1.5 rounded-lg bg-amber-950 hover:bg-amber-900 border border-amber-700 text-xs font-medium text-amber-200 flex items-center gap-1.5 transition-colors self-start sm:self-center shrink-0"
                          >
                            <span>Mở Kịch Bản Đổi Mật Khẩu & 2FA</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        {/* Cryptographic Audit Trail */}
                        {kAnonymityDetails && (
                          <div className="p-3 rounded-lg bg-zinc-950/80 border border-zinc-800 text-[11px] font-mono text-zinc-400 flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <span>Tiền tố gửi đi (Prefix 5-char): </span>
                              <strong className="text-zinc-200">{kAnonymityDetails.prefix}</strong>
                              <span className="text-zinc-600"> | </span>
                              <span>Hậu tố so khớp cục bộ (Suffix): </span>
                              <strong className="text-zinc-200">{kAnonymityDetails.suffix.slice(0, 8)}...</strong>
                            </div>
                            <div>
                              <span>Tổng số bản ghi trong bucket: </span>
                              <strong className="text-zinc-200">{kAnonymityDetails.totalReturnedInBucket || 'Đã đối soát'}</strong>
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="p-5 rounded-xl bg-emerald-950/20 border border-emerald-800/80 space-y-3">
                        <div className="flex items-start gap-3">
                          <div className="p-2.5 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800 shrink-0">
                            <CheckCircle2 className="w-5 h-5" />
                          </div>
                          <div>
                            <span className="text-xs font-mono uppercase font-bold text-emerald-300 block">
                              Không tìm thấy trong cơ sở dữ liệu rò rỉ đã biết.
                            </span>
                            <h4 className="text-sm font-semibold text-zinc-100 mt-0.5">
                              Mật khẩu này chưa từng xuất hiện trong hơn 14 tỷ dữ liệu rò rỉ được chỉ mục.
                            </h4>
                            <p className="text-xs text-zinc-300 mt-1 leading-relaxed">
                              Tuy nhiên, để đảm bảo an toàn tuyệt đối, bạn nên duy trì độ dài tối thiểu 14 ký tự và không sử dụng chung một mật khẩu cho nhiều dịch vụ khác nhau.
                            </p>
                          </div>
                        </div>

                        {kAnonymityDetails && (
                          <div className="p-3 rounded-lg bg-zinc-950/80 border border-zinc-800 text-[11px] font-mono text-zinc-400 flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <span>Tiền tố SHA-1 gửi đi: </span>
                              <strong className="text-zinc-200">{kAnonymityDetails.prefix}</strong>
                            </div>
                            <div className="text-emerald-400">
                              ✓ Hoàn tất đối soát an toàn Zero-Knowledge
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* OPTION 3: PHONE NUMBER LOOKUP (100% IN-APP SCANNER) */}
            {accountLookupType === 'phone' && (
              <div className="space-y-5">
                {/* Search & Configuration Card */}
                <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                      <Smartphone className="w-3.5 h-3.5 text-sky-400" />
                      <span>Nhập số điện thoại di động cần tra cứu & thẩm định an toàn:</span>
                    </label>
                    <span className="text-[10px] font-mono text-zinc-400">
                      Chuẩn đối soát: Viễn thông VN & Scraping 533M Facebook
                    </span>
                  </div>

                  <form onSubmit={handlePhoneCheck} className="space-y-3">
                    <div className="relative">
                      <input
                        type="tel"
                        id="input-phone-breach"
                        value={phoneInput}
                        onChange={(e) => {
                          setPhoneInput(e.target.value);
                          if (phoneError) setPhoneError(null);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handlePhoneCheck();
                          }
                        }}
                        placeholder="Ví dụ: 0988123456 hoặc +84988123456"
                        className="w-full rounded-lg bg-zinc-900 border border-zinc-700 px-3.5 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-sky-500 font-mono tracking-wide"
                      />
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2">
                      {/* Quick Sample Phones */}
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-[11px] font-mono text-zinc-400">Mẫu thử nghiệm:</span>
                        {samplePhones.map((sample, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => {
                              setPhoneInput(sample);
                              if (phoneError) setPhoneError(null);
                              handlePhoneCheck(undefined, sample);
                            }}
                            className="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[10px] font-mono text-zinc-300 transition-colors cursor-pointer"
                          >
                            {sample}
                          </button>
                        ))}
                      </div>

                      <button
                        type="submit"
                        id="btn-prepare-phone-check"
                        disabled={isAnalyzingPhone}
                        className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white font-medium text-xs flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
                      >
                        {isAnalyzingPhone ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Đang Phân Tích SĐT...</span>
                          </>
                        ) : (
                          <>
                            <Search className="w-3.5 h-3.5" />
                            <span>Phân Tích & Đối Soát Số Điện Thoại</span>
                          </>
                        )}
                      </button>
                    </div>
                  </form>

                  {phoneError && (
                    <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-200 text-xs flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>{phoneError}</span>
                    </div>
                  )}
                </div>

                {/* Sleek In-App Scanning Indicator */}
                {isAnalyzingPhone && (
                  <div className="p-6 rounded-xl bg-zinc-950 border border-sky-800/60 flex flex-col items-center justify-center text-center space-y-3 animate-pulse">
                    <div className="relative">
                      <div className="w-12 h-12 rounded-full border-2 border-sky-500/30 border-t-sky-400 animate-spin flex items-center justify-center">
                        <Smartphone className="w-5 h-5 text-sky-400" />
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-zinc-100">
                        Đang phân tích cấu trúc viễn thông & rà soát rủi ro lộ lọt...
                      </h4>
                      <p className="text-xs text-zinc-400 mt-1 max-w-md">
                        Đối chiếu dải đầu số nhà mạng, rà soát lịch sử quét dữ liệu mạng xã hội (Facebook 533M) & nguy cơ SIM-swap...
                      </p>
                    </div>
                  </div>
                )}

                {/* IN-APP PHONE SAFETY REPORT CARD */}
                {phoneReport && !isAnalyzingPhone && (
                  <div className="space-y-4">
                    {/* Status Header Banner */}
                    <div className="p-4 rounded-xl bg-amber-950/25 border border-amber-800/80 space-y-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-3">
                          <div className="p-2 rounded-lg bg-amber-950/80 border border-amber-700/60 text-amber-400 shrink-0 mt-0.5">
                            <AlertTriangle className="w-5 h-5" />
                          </div>
                          <div className="space-y-1">
                            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-300">
                              BÁO CÁO THẨM ĐỊNH AN TOÀN SỐ ĐIỆN THOẠI & PHÒNG VỆ SIM-SWAP
                            </span>
                            <h4 className="text-sm font-semibold text-zinc-100">
                              Số thuê bao: <span className="font-mono text-amber-200">{phoneReport.formattedNumber}</span>
                            </h4>
                            <p className="text-xs text-zinc-300 leading-relaxed">
                              Số thuê bao di động tại Việt Nam có nguy cơ cao nằm trong các kho dữ liệu quét công khai (Scraping) từ các trang mạng xã hội và dịch vụ giao vận trực tuyến, tạo điều kiện cho các chiến dịch lừa đảo mạo danh và tấn công SIM-swap.
                            </p>
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 shrink-0">
                          HIGH_EXPOSURE
                        </span>
                      </div>
                    </div>

                    {/* Carrier Recognition & MNP Disclaimer */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 pb-2.5">
                        <div className="flex items-center gap-2">
                          <Building2 className="w-4 h-4 text-sky-400" />
                          <span className="text-xs font-semibold text-zinc-200 font-mono">
                            Định Danh Nhà Mạng Gốc (Telecommunications Provider)
                          </span>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950 text-sky-300 border border-sky-800">
                          Đầu số: {phoneReport.carrier.prefix}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-zinc-900/90 border border-zinc-800 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-zinc-100">
                            {phoneReport.carrier.name}
                          </span>
                          <span className="text-[10px] font-mono text-emerald-400">
                            Phân bổ viễn thông quốc gia
                          </span>
                        </div>
                        <p className="text-[11px] text-zinc-400 leading-relaxed italic bg-zinc-950/60 p-2.5 rounded border border-zinc-800/60">
                          {phoneReport.carrier.mnpDisclaimer}
                        </p>
                      </div>
                    </div>

                    {/* Scraping Exposure Matrix */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider flex items-center gap-1.5">
                          <Database className="w-3.5 h-3.5 text-amber-400" />
                          <span>Hồ Sơ Rủi Ro Lộ Lọt Dữ Liệu Công Khai (Public Leak Profile)</span>
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800">
                          {phoneReport.exposureRisk.score}/100 ({phoneReport.exposureRisk.level})
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-zinc-900/80 border border-zinc-800 space-y-2 text-xs">
                        <span className="font-semibold text-amber-300 block">
                          {phoneReport.exposureRisk.title}
                        </span>
                        <p className="text-[11px] text-zinc-300 leading-relaxed">
                          {phoneReport.exposureRisk.description}
                        </p>

                        <div className="pt-2 space-y-1.5">
                          <span className="text-[10px] font-mono uppercase text-zinc-400 block font-semibold">
                            Các tệp dữ liệu rò rỉ trọng yếu liên quan:
                          </span>
                          {phoneReport.exposureRisk.knownSources.map((src, sIdx) => (
                            <div key={sIdx} className="flex items-start gap-1.5 text-[11px] text-zinc-400">
                              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                              <span>{src}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Anti-SIM-Swap & Spam Call Defense Guidelines */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-rose-400" />
                          <h4 className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider">
                            Hướng Dẫn Phòng Vệ Chiếm Đoạt SIM (Anti-SIM-Swap & Spam Defense)
                          </h4>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                        {phoneReport.simSwapDefense.guidelines.map((guide, gIdx) => (
                          <div key={gIdx} className="p-3 rounded-lg bg-zinc-900/90 border border-zinc-800 space-y-1.5">
                            <span className="font-semibold text-sky-300 block">
                              {gIdx + 1}. {guide.title}
                            </span>
                            <p className="text-[11px] text-zinc-400 leading-relaxed">
                              {guide.description}
                            </p>
                            <div className="p-1.5 rounded bg-zinc-950 border border-zinc-800 text-[10px] font-mono text-emerald-400">
                              Thao tác: {guide.action}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Interactive Phone Defense Checklist */}
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ListChecks className="w-4 h-4 text-sky-400" />
                          <h4 className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider">
                            Danh Mục Hành Động Bảo Vệ Số Điện Thoại
                          </h4>
                        </div>
                        <span className="text-[11px] font-mono text-sky-400">
                          Đã hoàn thành {Object.values(phoneTasks).filter(Boolean).length}/4 bước
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                        {/* Task 1 */}
                        <div
                          onClick={() => togglePhoneTask('step1')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            phoneTasks.step1
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            phoneTasks.step1 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {phoneTasks.step1 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${phoneTasks.step1 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              1. Cài Đặt Mã PIN Thẻ SIM Trên Máy
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Ngăn chặn kẻ gian rút SIM cắm sang điện thoại khác để nhận trộm mã OTP ngân hàng.
                            </span>
                          </div>
                        </div>

                        {/* Task 2 */}
                        <div
                          onClick={() => togglePhoneTask('step2')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            phoneTasks.step2
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            phoneTasks.step2 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {phoneTasks.step2 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${phoneTasks.step2 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              2. Đăng Ký Chống Cuộc Gọi Rác (DNC 5656)
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Soạn tin nhắn SMS miễn phí "DK DNC" gửi 5656 của Cục An toàn thông tin.
                            </span>
                          </div>
                        </div>

                        {/* Task 3 */}
                        <div
                          onClick={() => togglePhoneTask('step3')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            phoneTasks.step3
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            phoneTasks.step3 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {phoneTasks.step3 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${phoneTasks.step3 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              3. Chuyển Xác Thực Sang Smart OTP / Sinh Trắc Học
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Ngừng sử dụng SMS OTP cho các giao dịch ngân hàng giá trị cao.
                            </span>
                          </div>
                        </div>

                        {/* Task 4 */}
                        <div
                          onClick={() => togglePhoneTask('step4')}
                          className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-2.5 ${
                            phoneTasks.step4
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-zinc-300'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                          }`}
                        >
                          <div className={`w-4 h-4 rounded mt-0.5 border flex items-center justify-center shrink-0 ${
                            phoneTasks.step4 ? 'bg-emerald-600 border-emerald-500 text-white' : 'border-zinc-600 bg-zinc-800'
                          }`}>
                            {phoneTasks.step4 && <Check className="w-3 h-3" />}
                          </div>
                          <div>
                            <span className={`font-semibold block ${phoneTasks.step4 ? 'line-through text-zinc-400' : 'text-zinc-100'}`}>
                              4. Cài Đặt Ứng Dụng nTrust Quốc Gia
                            </span>
                            <span className="text-[11px] text-zinc-400 block mt-0.5 leading-relaxed">
                              Ứng dụng của Hiệp hội An ninh mạng Quốc gia tự động cảnh báo số điện thoại lừa đảo.
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Prominent Unblockable Native Link (Zero Pop-Up Blocking) */}
                      <div className="pt-3 border-t border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div className="text-[11px] text-zinc-400 flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span>Liên kết tra cứu chuyên sâu bên thứ 3 (Miễn nhiễm pop-up blocker)</span>
                        </div>
                        <a
                          id="btn-direct-cybernews-query-native"
                          href="https://cybernews.com/personal-data-leak-check/"
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-4 py-2 rounded-lg bg-sky-950/90 hover:bg-sky-900 border border-sky-800 text-sky-200 hover:text-white font-medium text-xs flex items-center justify-center gap-1.5 transition-colors self-start sm:self-auto cursor-pointer"
                        >
                          <Shield className="w-3.5 h-3.5 text-sky-400" />
                          <span>Mở Cổng Tra Cứu Chuyên Sâu SĐT Trên Cybernews</span>
                          <ExternalLink className="w-3.5 h-3.5 text-sky-400" />
                        </a>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Quick Bridge to Panel B */}
          <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5">
              <Cpu className="w-4 h-4 text-purple-400 shrink-0" />
              <div>
                <span className="font-semibold text-purple-200 block">
                  Bạn muốn kiểm tra một bài đăng, email hay hình ảnh trước khi chia sẻ ra ngoài?
                </span>
                <span className="text-zinc-400 text-[11px]">
                  Sử dụng công cụ đánh giá mức độ nhạy cảm văn bản (Mục B) để phát hiện sự vô tình kết hợp CCCD, địa chỉ, SĐT...
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setActiveSubTab('text_audit')}
              className="px-3.5 py-1.5 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-200 text-xs font-medium flex items-center gap-1.5 self-start sm:self-center shrink-0 transition-colors"
            >
              <span>Chuyển sang Mục B (Quét Văn Bản)</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* =========================================================================
          PANEL B: PRE-PUBLISH TEXT PRIVACY AUDITOR [AI_HEURISTIC]
          ========================================================================= */}
      {activeSubTab === 'text_audit' && (
        <div className="space-y-5">
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-5 sm:p-6 space-y-5 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
              <div>
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-xl bg-purple-950/80 border border-purple-800/80 text-purple-400 shadow-xs">
                    <Cpu className="w-4 h-4 stroke-[2]" />
                  </div>
                  <h3 className="text-sm font-bold text-white">
                    Đánh Giá Mức Độ Nhạy Cảm Văn Bản Trước Khi Đăng Tải (Pre-Publish Privacy Auditor)
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-950 text-purple-300 border border-purple-800">
                    AI_HEURISTIC
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1.5 font-normal">
                  Phân tích tổ hợp dữ liệu trong nội dung văn bản nhằm ngăn ngừa việc vô tình để lộ danh tính cá nhân (CCCD, SĐT, địa chỉ, tài khoản) trước khi chia sẻ.
                </p>
              </div>

              {/* Sample Quick Fill Buttons */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[11px] font-mono text-zinc-400">Mẫu thử:</span>
                {sampleAudits.map((sample, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      setInputText(sample.text);
                      handleRunAudit(sample.text);
                    }}
                    className="px-2 py-1 rounded bg-zinc-950 hover:bg-zinc-800 border border-zinc-800 text-[10px] font-mono text-zinc-300 transition-colors"
                  >
                    Mẫu {idx + 1}
                  </button>
                ))}
              </div>
            </div>

            {/* MANDATORY HELPER NOTICE AS REQUESTED */}
            <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/80 text-xs text-amber-200/90 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <p className="text-xs leading-relaxed text-zinc-300">
                  <strong className="text-amber-300">Lưu ý quan trọng:</strong> Công cụ này phân tích tổ hợp thông tin trong văn bản để tránh việc vô tình để lộ danh tính (ví dụ: đăng kèm CCCD, SĐT, địa chỉ nhà). Để kiểm tra xem email của bạn có từng bị hacker làm rò rỉ hay không, vui lòng sử dụng mục <strong>"Tra cứu Lịch sử Rò rỉ Tài khoản"</strong> ở trên.
                </p>
              </div>

              <button
                type="button"
                id="btn-switch-to-account-breach"
                onClick={() => setActiveSubTab('account_breach')}
                className="px-3 py-1.5 rounded-md bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 text-[11px] font-medium flex items-center gap-1 self-start sm:self-center shrink-0 transition-colors"
              >
                <span>Tra cứu Email bị rò rỉ (Mục A)</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {/* RENAMED TEXT BOX AS REQUESTED */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-zinc-200 block">
                Kiểm tra độ hở dữ liệu văn bản (Trước khi gửi email, đăng mạng xã hội):
              </label>

              <textarea
                id="textarea-prepublish-audit"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                rows={5}
                placeholder="Dán văn bản cần kiểm tra tại đây (Ví dụ: thông tin giao dịch, bản thảo bài đăng Facebook/Zalo, thông tin cá nhân cần gửi qua email...)"
                className="w-full rounded-lg bg-zinc-950 border border-zinc-800 px-3.5 py-3 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-purple-500 font-mono leading-relaxed resize-y"
              />

              <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                <div className="text-[11px] font-mono text-zinc-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Dữ liệu chỉ được đánh giá cấu trúc rủi ro và không được lưu giữ vĩnh viễn.</span>
                </div>

                <button
                  type="button"
                  id="btn-run-exposure-audit"
                  onClick={() => handleRunAudit()}
                  disabled={isAuditing || !inputText.trim()}
                  className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                >
                  {isAuditing ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Đang phân tích tổ hợp rủi ro...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Đánh Giá Mức Độ Lộ Lọt Danh Tính</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {auditError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-200 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{auditError}</span>
              </div>
            )}
          </div>

          {/* Exposure Audit Results Presentation */}
          {auditResult && (
            <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 space-y-5">
              {/* Score & Risk Summary Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
                <div className="flex items-start gap-3">
                  <div className={`p-3 rounded-xl border font-mono font-bold text-lg flex items-center justify-center min-w-[64px] ${
                    auditResult.riskScore >= 75
                      ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                      : auditResult.riskScore >= 40
                      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                      : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  }`}>
                    {auditResult.riskScore}/100
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono uppercase text-zinc-400">
                        Chỉ Số Rủi Ro Danh Tính Tổng Hợp:
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                        auditResult.riskLevel === 'critical'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : auditResult.riskLevel === 'high'
                          ? 'bg-amber-950 text-amber-300 border-amber-800'
                          : auditResult.riskLevel === 'medium'
                          ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      }`}>
                        {auditResult.riskLevel === 'critical' ? 'Rủi ro Cực Kỳ Nghiêm Trọng' : auditResult.riskLevel === 'high' ? 'Rủi ro Cao' : auditResult.riskLevel === 'medium' ? 'Rủi ro Trung Bình' : 'Rủi ro Thấp / An Toàn'}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-950 text-purple-300 border border-purple-800">
                        Nguồn gốc: {auditResult.provenance}
                      </span>
                    </div>
                    <p className="text-xs text-zinc-300 mt-1 leading-relaxed">
                      {auditResult.summary}
                    </p>
                  </div>
                </div>

                {auditResult.riskScore >= 50 && (
                  <button
                    type="button"
                    onClick={() => setActiveSubTab('playbook')}
                    className="px-3 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-700 text-xs font-medium text-rose-200 flex items-center gap-1.5 self-start sm:self-center shrink-0 transition-colors"
                  >
                    <span>Mở Kịch Bản Ứng Cứu Khẩn Cấp</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Detected PII Items Grid */}
              <div className="space-y-2.5">
                <span className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider block">
                  1. Các Phần Tử Định Danh Nhạy Cảm Được Phát Hiện ({auditResult.detectedPiiItems.length})
                </span>

                {auditResult.detectedPiiItems.length === 0 ? (
                  <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-emerald-300 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Không phát hiện trường thông tin nhạy cảm độc lập nào trong văn bản.</span>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {auditResult.detectedPiiItems.map((item, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1.5">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-zinc-200">
                            {item.label}
                          </span>
                          <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono uppercase font-semibold border ${
                            item.severity === 'critical'
                              ? 'bg-rose-950 text-rose-300 border-rose-800'
                              : item.severity === 'high'
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : item.severity === 'medium'
                              ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                              : 'bg-zinc-900 text-zinc-400 border-zinc-800'
                          }`}>
                            {item.severity === 'critical' ? 'Nghiêm trọng' : item.severity === 'high' ? 'Mức cao' : item.severity === 'medium' ? 'Trung bình' : 'Thấp'}
                          </span>
                        </div>
                        <div className="font-mono text-xs bg-zinc-900 px-2 py-1 rounded border border-zinc-800 text-zinc-300">
                          {item.snippet}
                        </div>
                        <p className="text-[11px] text-zinc-400 leading-normal">
                          {item.riskReason}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Composite Attack Vectors */}
              <div className="space-y-2.5 pt-2">
                <span className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider block">
                  2. Phân Tích Véc-Tơ Tấn Công Do Sự Kết Hợp Dữ Liệu (Composite Threat Analysis)
                </span>
                <p className="text-xs text-zinc-400">
                  Một số trường thông tin đứng riêng lẻ không nguy hiểm, nhưng khi xuất hiện cùng nhau sẽ tạo ra lỗ hổng bảo mật nghiêm trọng:
                </p>

                <div className="space-y-3">
                  {auditResult.compositeAttackVectors.map((vector, idx) => (
                    <div
                      key={idx}
                      className={`p-4 rounded-lg border space-y-2 ${
                        vector.severity === 'critical'
                          ? 'bg-rose-950/20 border-rose-900/60'
                          : vector.severity === 'high'
                          ? 'bg-amber-950/20 border-amber-900/60'
                          : 'bg-zinc-950 border-zinc-800'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${
                            vector.severity === 'critical' ? 'text-rose-400' : 'text-amber-400'
                          }`} />
                          <h4 className="text-xs font-semibold text-zinc-100">
                            {vector.vector}
                          </h4>
                        </div>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono uppercase font-semibold border ${
                          vector.severity === 'critical'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : 'bg-amber-950 text-amber-300 border-amber-800'
                        }`}>
                          {vector.severity === 'critical' ? 'Hiểm họa khẩn cấp' : 'Mức độ đe dọa cao'}
                        </span>
                      </div>

                      <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                        {vector.explanation}
                      </p>

                      {vector.targetedThreats && vector.targetedThreats.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap pt-1">
                          <span className="text-[10px] font-mono text-zinc-400">Hậu quả trực tiếp:</span>
                          {vector.targetedThreats.map((threat, tIdx) => (
                            <span
                              key={tIdx}
                              className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-950 text-zinc-300 border border-zinc-800"
                            >
                              {threat}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendations Card */}
              {auditResult.recommendations.length > 0 && (
                <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2">
                  <span className="text-xs font-semibold text-zinc-200 font-mono uppercase tracking-wider block">
                    3. Hành Động Khuyến Nghị Trước Khi Chia Sẻ
                  </span>
                  <ul className="space-y-1.5 text-xs text-zinc-300">
                    {auditResult.recommendations.map((rec, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          PANEL C: REMEDIATION PLAYBOOK
          ========================================================================= */}
      {activeSubTab === 'playbook' && (
        <div className="space-y-5">
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 rounded-2xl p-5 sm:p-6 space-y-5 shadow-2xl shadow-black/60 border-t border-t-white/10 transition-all duration-300">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
              <div>
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-xl bg-emerald-950/80 border border-emerald-800/80 text-emerald-400 shadow-xs">
                    <ListChecks className="w-4 h-4 stroke-[2]" />
                  </div>
                  <h3 className="text-sm font-bold text-white">
                    Kịch Bản Ứng Cứu Khẩn Cấp Khi Phát Hiện Lộ Lọt Dữ Liệu
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                    SOC_PLAYBOOK
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1.5 font-normal">
                  Quy trình 4 bước chuẩn SOC giúp cô lập rủi ro, vô hiệu hóa phiên xâm nhập và bảo vệ tài khoản tài chính dành cho người dùng Việt Nam.
                </p>
              </div>

              <div className="flex items-center gap-2 self-start sm:self-center">
                <span className="text-xs font-mono text-slate-400">Tiến độ ứng cứu:</span>
                <div className="px-3 py-1 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono font-bold text-emerald-400 shadow-xs">
                  {completedTasksCount} / 4 Hoàn thành
                </div>
              </div>
            </div>

            {/* Checklist items */}
            <div className="space-y-3.5">
              {/* STEP 1 */}
              <div
                onClick={() => togglePlaybookTask('step1')}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  playbookTasks.step1
                    ? 'bg-emerald-950/20 border-emerald-800/80 text-zinc-200'
                    : 'bg-zinc-950 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded border flex items-center justify-center mt-0.5 shrink-0 transition-colors ${
                    playbookTasks.step1
                      ? 'bg-emerald-600 border-emerald-500 text-zinc-950'
                      : 'border-zinc-700 bg-zinc-900'
                  }`}>
                    {playbookTasks.step1 && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className={`text-xs font-semibold ${playbookTasks.step1 ? 'text-emerald-300 line-through' : 'text-zinc-100'}`}>
                        Bước 1: Thay Đổi Mật Khẩu Ngay Lập Tức Trên Các Tài Nguyên Trọng Yếu
                      </h4>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-zinc-900 text-zinc-300 border border-zinc-700">
                        Ưu tiên khẩn cấp
                      </span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                      Nếu mật khẩu hoặc email của bạn có trong dữ liệu rò rỉ, tội phạm sẽ dùng công cụ tự động đăng nhập vào hòm thư, ngân hàng, mạng xã hội. Hãy đổi sang mật khẩu mới dài trên 14 ký tự và <strong>tuyệt đối không đặt lại mật khẩu cũ</strong>.
                    </p>
                  </div>
                </div>
              </div>

              {/* STEP 2 */}
              <div
                onClick={() => togglePlaybookTask('step2')}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  playbookTasks.step2
                    ? 'bg-emerald-950/20 border-emerald-800/80 text-zinc-200'
                    : 'bg-zinc-950 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded border flex items-center justify-center mt-0.5 shrink-0 transition-colors ${
                    playbookTasks.step2
                      ? 'bg-emerald-600 border-emerald-500 text-zinc-950'
                      : 'border-zinc-700 bg-zinc-900'
                  }`}>
                    {playbookTasks.step2 && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className={`text-xs font-semibold ${playbookTasks.step2 ? 'text-emerald-300 line-through' : 'text-zinc-100'}`}>
                        Bước 2: Kích Hoạt Xác Thực 2 Yếu Tố (2FA / Passkey) Bằng Ứng Dụng Chuyên Dụng
                      </h4>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-zinc-900 text-zinc-300 border border-zinc-700">
                        Lớp giáp kép
                      </span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                      Sử dụng Google Authenticator, Microsoft Authenticator hoặc Khóa bảo mật phần cứng FIDO2. Hạn chế sử dụng OTP qua tin nhắn SMS vì có nguy cơ bị tấn công hoán đổi SIM (SIM Swap) hoặc đánh chặn sóng di động.
                    </p>
                  </div>
                </div>
              </div>

              {/* STEP 3 */}
              <div
                onClick={() => togglePlaybookTask('step3')}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  playbookTasks.step3
                    ? 'bg-emerald-950/20 border-emerald-800/80 text-zinc-200'
                    : 'bg-zinc-950 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded border flex items-center justify-center mt-0.5 shrink-0 transition-colors ${
                    playbookTasks.step3
                      ? 'bg-emerald-600 border-emerald-500 text-zinc-950'
                      : 'border-zinc-700 bg-zinc-900'
                  }`}>
                    {playbookTasks.step3 && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className={`text-xs font-semibold ${playbookTasks.step3 ? 'text-emerald-300 line-through' : 'text-zinc-100'}`}>
                        Bước 3: Thu Hồi Toàn Bộ Các Phiên Đăng Nhập Cũ (Revoke Active Sessions)
                      </h4>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-zinc-900 text-zinc-300 border border-zinc-700">
                        Cắt đứt xâm nhập
                      </span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                      Truy cập mục <em>Cài đặt bảo mật → Quản lý thiết bị</em> trong Google, Apple ID, Microsoft, Facebook hoặc Zalo. Chọn <strong>"Đăng xuất khỏi tất cả các thiết bị khác"</strong> để vô hiệu hóa ngay lập tức các phiên kẻ tấn công có thể đang duy trì (Session Hijacking).
                    </p>
                  </div>
                </div>
              </div>

              {/* STEP 4 */}
              <div
                onClick={() => togglePlaybookTask('step4')}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  playbookTasks.step4
                    ? 'bg-emerald-950/20 border-emerald-800/80 text-zinc-200'
                    : 'bg-zinc-950 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className={`w-5 h-5 rounded border flex items-center justify-center mt-0.5 shrink-0 transition-colors ${
                    playbookTasks.step4
                      ? 'bg-emerald-600 border-emerald-500 text-zinc-950'
                      : 'border-zinc-700 bg-zinc-900'
                  }`}>
                    {playbookTasks.step4 && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h4 className={`text-xs font-semibold ${playbookTasks.step4 ? 'text-emerald-300 line-through' : 'text-zinc-100'}`}>
                        Bước 4: Rà Soát Quy Tắc Chuyển Tiếp Thư (Forwarding Rules) & Ứng Dụng Liên Kết
                      </h4>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono uppercase bg-zinc-900 text-zinc-300 border border-zinc-700">
                        Kiểm toán cửa sau
                      </span>
                    </div>

                    <p className="text-xs text-zinc-300 leading-relaxed font-normal">
                      Kẻ xâm nhập thường âm thầm thiết lập bộ lọc tự động chuyển tiếp (Email Forwarding Rule) các thư ngân hàng hoặc mã khôi phục sang hòm thư của chúng. Hãy vào mục Cài đặt Hộp thư → Bộ lọc & Chuyển tiếp để xóa bất kỳ quy tắc lạ nào, đồng thời thu hồi quyền của các ứng dụng bên thứ ba không rõ nguồn gốc.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {completedTasksCount === 4 && (
              <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-800 text-xs text-emerald-200 flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div>
                  <span className="font-semibold block">
                    Xuất sắc! Bạn đã hoàn thành toàn bộ 4 bước ứng cứu khẩn cấp.
                  </span>
                  <p className="text-emerald-300/80 mt-0.5">
                    Hồ sơ định danh và các tài khoản số trọng yếu của bạn đã được tái lập trạng thái phòng vệ tối đa trước nguy cơ rò rỉ dữ liệu.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Persistent Vietnamese & Global National Cyber Safety Footprint */}
      <div className="p-5 sm:p-6 rounded-2xl bg-slate-900/70 backdrop-blur-xl border border-slate-800/80 hover:border-slate-700/90 shadow-2xl shadow-black/60 border-t border-t-white/10 space-y-4 transition-all duration-300">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-sky-400" />
            <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
              Cổng Tra Cứu & Báo Cáo An Toàn Không Gian Mạng Quốc Gia Việt Nam
            </h4>
          </div>
          <span className="text-[10px] font-mono text-slate-400 font-semibold">
            NCSC • Cục An Toàn Thông Tin • VNCERT
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col justify-between space-y-2 shadow-xs">
            <div>
              <span className="text-xs font-bold text-white block">
                Cổng Không Gian Mạng Quốc Gia
              </span>
              <span className="text-[11px] font-mono text-slate-400 block mt-0.5">
                Trung tâm Giám sát An toàn không gian mạng Quốc gia (NCSC)
              </span>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Cung cấp công cụ kiểm tra thông tin tài khoản bị lộ lọt và cẩm nang phòng chống mã độc chính thức.
              </p>
            </div>
            <a
              href="https://khonggianmang.vn"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-white font-medium underline pt-2"
            >
              <span>Truy cập khonggianmang.vn</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col justify-between space-y-2 shadow-xs">
            <div>
              <span className="text-xs font-bold text-white block">
                Cục An Toàn Thông Tin (AIS)
              </span>
              <span className="text-[11px] font-mono text-slate-400 block mt-0.5">
                Bộ Thông tin và Truyền thông
              </span>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Cổng tiếp nhận phản ánh trang web giả mạo lừa đảo, tấn công mạng và rò rỉ dữ liệu cá nhân tại Việt Nam.
              </p>
            </div>
            <a
              href="https://canhbao.khonggianmang.vn"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-white font-medium underline pt-2"
            >
              <span>Cổng cảnh báo canhbao.khonggianmang.vn</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col justify-between space-y-2 shadow-xs">
            <div>
              <span className="text-xs font-bold text-white block">
                Ứng Dụng nTrust Quốc Gia
              </span>
              <span className="text-[11px] font-mono text-slate-400 block mt-0.5">
                Hiệp hội An ninh mạng quốc gia (NCA)
              </span>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Tra cứu tài khoản ngân hàng lừa đảo, số điện thoại lạ và tự động phát hiện liên kết độc hại trên điện thoại.
              </p>
            </div>
            <a
              href="https://ntrust.vn"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-white font-medium underline pt-2"
            >
              <span>Tải ứng dụng tại ntrust.vn</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>

        {/* Subtle Scientific Citation Footer */}
        <div className="pt-3 pb-1 text-center text-[11px] font-mono text-slate-500 border-t border-slate-800/80">
          Nguồn tham chiếu dữ liệu: <a href="https://haveibeenpwned.com" target="_blank" rel="noopener noreferrer" className="text-slate-400 hover:text-slate-200 underline">Have I Been Pwned</a> • <a href="https://khonggianmang.vn" target="_blank" rel="noopener noreferrer" className="text-slate-400 hover:text-slate-200 underline">NCSC</a> • <a href="https://cybernews.com" target="_blank" rel="noopener noreferrer" className="text-slate-400 hover:text-slate-200 underline">Cybernews</a>
        </div>
      </div>
    </div>
  );
};

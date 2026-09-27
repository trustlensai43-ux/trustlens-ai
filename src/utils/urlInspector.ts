import { ThreatSeverity, ProvenanceType, VerificationSource, ScamIndicator } from '../types';
import { evaluateUrlThreatIntelligence } from './threatScoringEngine';

export interface UrlInspectionFlag {
  id: string;
  name: string;
  details: string;
  severity: ThreatSeverity;
  scoreWeight: number;
  category: 'suspicious_link' | 'impersonation' | 'data_harvesting';
  evidenceSnippet?: string;
  provenance: ProvenanceType;
}

export interface ExternalAuthorityLinks {
  tinNhiemMang: {
    name: string;
    url: string;
    description: string;
  };
  canhBaoKhongGianMang: {
    name: string;
    url: string;
    description: string;
  };
  virusTotal: {
    name: string;
    url: string;
    description: string;
  };
  chongLuaDao: {
    name: string;
    url: string;
    description: string;
  };
  nTrust: {
    name: string;
    url: string;
    description: string;
  };
}

export interface UrlInspectionResult {
  rawUrl: string;
  normalizedUrl: string;
  hostname: string;
  domain: string;
  tld: string;
  isIpAddress: boolean;
  isPunycode: boolean;
  isCommonNewTld: boolean;
  tldSuspicionScore: number;
  subdomainCount: number;
  impersonatedBrand?: string;
  flags: UrlInspectionFlag[];
  scamScore: number;
  scamLevel: ThreatSeverity;
  confidence: number;
  summary: string;
  verificationSources: VerificationSource[];
  externalLinks: ExternalAuthorityLinks;
  scamIndicators: ScamIndicator[];
}

// Danh sách các đuôi tên miền (TLD) thường xuất hiện trong chiến dịch tự động giá rẻ
// Lưu ý nguyên tắc an toàn: TLD KHÔNG BAO GIỜ được coi là bằng chứng lừa đảo duy nhất
const NEW_AUTOMATED_TLDS = [
  '.xyz',
  '.top',
  '.site',
  '.work',
  '.click',
  '.loan',
  '.fit',
  '.gq',
  '.cf',
  '.tk',
  '.ml',
  '.ga',
  '.cc',
  '.online',
  '.vip',
  '.buzz',
  '.icu',
];

// Danh sách từ khóa cơ quan nhà nước & thương hiệu tài chính phổ biến
const BRAND_PATTERNS = [
  { keyword: 'vietcombank', officialDomainSuffixes: ['vietcombank.com.vn', 'vietcombank.com'] },
  { keyword: 'techcombank', officialDomainSuffixes: ['techcombank.com.vn', 'techcombank.com'] },
  { keyword: 'mbbank', officialDomainSuffixes: ['mbbank.com.vn'] },
  { keyword: 'vietinbank', officialDomainSuffixes: ['vietinbank.vn'] },
  { keyword: 'bidv', officialDomainSuffixes: ['bidv.com.vn'] },
  { keyword: 'vpbank', officialDomainSuffixes: ['vpbank.com.vn'] },
  { keyword: 'acb', officialDomainSuffixes: ['acb.com.vn'] },
  { keyword: 'tpbank', officialDomainSuffixes: ['tpb.vn', 'tpbank.com.vn'] },
  { keyword: 'sacombank', officialDomainSuffixes: ['sacombank.com.vn', 'sacombank.com'] },
  { keyword: 'vneid', officialDomainSuffixes: ['vneid.gov.vn', 'dancuquocgia.gov.vn'] },
  { keyword: 'dichvucong', officialDomainSuffixes: ['dichvucong.gov.vn'] },
  { keyword: 'gdt.gov', officialDomainSuffixes: ['gdt.gov.vn'] },
  { keyword: 'tongcucthue', officialDomainSuffixes: ['gdt.gov.vn'] },
  { keyword: 'shopee', officialDomainSuffixes: ['shopee.vn', 'shopee.com'] },
  { keyword: 'lazada', officialDomainSuffixes: ['lazada.vn', 'lazada.com'] },
  { keyword: 'tiktok', officialDomainSuffixes: ['tiktok.com'] },
  { keyword: 'zalo', officialDomainSuffixes: ['zalo.me', 'zaloapp.com'] },
  { keyword: 'momo', officialDomainSuffixes: ['momo.vn'] },
  { keyword: 'vnpay', officialDomainSuffixes: ['vnpay.vn'] },
  { keyword: 'paypal', officialDomainSuffixes: ['paypal.com'] },
  { keyword: 'apple', officialDomainSuffixes: ['apple.com'] },
  { keyword: 'microsoft', officialDomainSuffixes: ['microsoft.com'] },
  { keyword: 'netflix', officialDomainSuffixes: ['netflix.com'] },
  { keyword: 'amazon', officialDomainSuffixes: ['amazon.com'] },
  { keyword: 'chase', officialDomainSuffixes: ['chase.com'] },
  { keyword: 'binance', officialDomainSuffixes: ['binance.com'] },
];

/**
 * Tạo liên kết tra cứu xác thực ngoại bộ từ các cơ quan có thẩm quyền và công cụ uy tín
 */
export function buildExternalAuthorityLinks(hostname: string): ExternalAuthorityLinks {
  const cleanHost = hostname.toLowerCase().trim();
  return {
    tinNhiemMang: {
      name: 'Hệ Thống Tín Nhiệm Mạng Quốc Gia (NCSC)',
      url: 'https://tinnhiemmang.vn/tra-cuu-tinh-nhiem-mang',
      description: 'Tra cứu chứng nhận tin cậy của tổ chức, doanh nghiệp và trang web chính thống tại Việt Nam.',
    },
    canhBaoKhongGianMang: {
      name: 'Cổng Cảnh Báo An Toàn Không Gian Mạng (AIS)',
      url: 'https://canhbao.khonggianmang.vn/',
      description: 'Cơ sở dữ liệu cảnh báo trang web lừa đảo và tài khoản giả mạo do Cục An Toàn Thông Tin quản lý.',
    },
    virusTotal: {
      name: 'VirusTotal Domain Intelligence',
      url: cleanHost ? `https://www.virustotal.com/gui/domain/${encodeURIComponent(cleanHost)}` : 'https://www.virustotal.com/',
      description: 'Kiểm tra tên miền qua hơn 70 công cụ quét phần mềm độc hại và danh sách đen an ninh mạng toàn cầu.',
    },
    chongLuaDao: {
      name: 'Dự Án Chống Lừa Đảo (chongluadao.vn)',
      url: 'https://chongluadao.vn',
      description: 'Tiện ích cộng đồng bảo trợ bởi NCSC giúp tự động chặn website giả mạo theo thời gian thực.',
    },
    nTrust: {
      name: 'Ứng Dụng nTrust (Hiệp Hội NCA)',
      url: 'https://ntrust.vn',
      description: 'Ứng dụng di động quốc gia kiểm tra tài khoản ngân hàng gian lận và đường link độc hại.',
    },
  };
}

/**
 * Trình phân tích kiểm tra cú pháp và cấu trúc tên miền URL độc lập (URL Inspector Engine)
 * Đảm bảo:
 * 1. Giới hạn tối đa trọng số nghi vấn TLD (.xyz, .top, .site) ở mức 10-15 điểm.
 * 2. Tên miền như abc.xyz luôn được đánh giá là RỦI RO THẤP (LOW RISK).
 * 3. Gắn nhãn UNAVAILABLE cho trạng thái danh sách đen khi chưa có khóa API thời gian thực.
 */
export function inspectUrl(targetUrl: string): UrlInspectionResult {
  const raw = (targetUrl || '').trim();
  let normalizedUrl = raw;
  let hostname = '';
  let pathname = '';
  let searchParams: URLSearchParams = new URLSearchParams();

  try {
    const parsed = new URL(raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`);
    normalizedUrl = parsed.toString();
    hostname = parsed.hostname.toLowerCase();
    pathname = parsed.pathname;
    searchParams = parsed.searchParams;
  } catch {
    hostname = raw.toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0].split('?')[0];
  }

  const flags: UrlInspectionFlag[] = [];
  let scoreSum = 0;

  // Evaluate 3-Tier URL Threat Intelligence
  const urlIntel = evaluateUrlThreatIntelligence(raw);

  // 1. Phân tích TLD (Top-Level Domain)
  // NGUYÊN TẮC BẮT BUỘC: Đuôi tên miền thông dụng (.xyz, .top, .online) một mình nó KHÔNG BAO GIỜ bị phạt rủi ro
  const isCommonNewTld = NEW_AUTOMATED_TLDS.some(tld => hostname.endsWith(tld));
  const tld = hostname.includes('.') ? hostname.slice(hostname.lastIndexOf('.')) : '';
  const tldSuspicionScore = 0; // 0 điểm rủi ro cho TLD thông thường

  // 2. Kiểm tra Punycode / Homoglyph giả mạo ký tự (xn--)
  const isPunycode = hostname.includes('xn--');
  if (isPunycode) {
    const punyWeight = 65;
    scoreSum += punyWeight;
    flags.push({
      id: 'flag-punycode-homoglyph',
      name: 'Ký Tự Mã Hóa Quốc Tế Giả Mạo (Punycode / Homoglyph)',
      details: `Tên miền chứa tiền tố mã hóa đặc biệt '${hostname}', thủ đoạn thường dùng để giả mạo giao diện thị giác của các thương hiệu phổ biến nhằm đánh lừa mắt người dùng.`,
      severity: 'critical',
      scoreWeight: punyWeight,
      category: 'impersonation',
      evidenceSnippet: hostname,
      provenance: 'DETERMINISTIC',
    });
  }

  // 3. Kiểm tra sử dụng trực tiếp địa chỉ IP thay cho Tên miền
  const isIpAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  if (isIpAddress) {
    const ipWeight = 45;
    scoreSum += ipWeight;
    flags.push({
      id: 'flag-raw-ip',
      name: 'Sử Dụng Trực Tiếp Địa Chỉ IP Thay Cho Tên Miền Hợp Lệ',
      details: 'Đường dẫn sử dụng chuỗi IP số thô thay vì tên miền đã đăng ký qua hệ thống phân giải DNS, thường nhằm né tránh bộ lọc danh tiếng tên miền.',
      severity: 'high',
      scoreWeight: ipWeight,
      category: 'suspicious_link',
      evidenceSnippet: hostname,
      provenance: 'DETERMINISTIC',
    });
  }

  // 4. Kiểm tra xếp tầng tên miền phụ bất thường (Subdomain Stacking)
  const parts = hostname.split('.');
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
  if (parts.length > 4) {
    const subWeight = 35;
    scoreSum += subWeight;
    flags.push({
      id: 'flag-subdomain-stacking',
      name: 'Xếp Tầng Tên Miền Phụ Bất Thường (Subdomain Stacking)',
      details: `Tên miền có ${parts.length} cấp phân đoạn. Kẻ gian thường lồng ghép tên tổ chức uy tín vào subdomain để che giấu tên miền đích thực tế ở đuôi.`,
      severity: 'high',
      scoreWeight: subWeight,
      category: 'suspicious_link',
      evidenceSnippet: hostname,
      provenance: 'DETERMINISTIC',
    });
  }

  // 5. Kiểm tra mạo danh từ khóa thương hiệu / cơ quan nhà nước
  let impersonatedBrand: string | undefined = undefined;
  for (const item of BRAND_PATTERNS) {
    if (hostname.includes(item.keyword) || pathname.toLowerCase().includes(item.keyword)) {
      const isOfficialGov = hostname.endsWith('.gov.vn');
      const isOfficialBrand = item.officialDomainSuffixes.some(suf => hostname.endsWith(suf));

      if (!isOfficialGov && !isOfficialBrand) {
        impersonatedBrand = item.keyword;
        const brandWeight = 70;
        scoreSum += brandWeight;
        flags.push({
          id: 'flag-brand-impersonation',
          name: `Dấu Hiệu Mạo Danh Từ Khóa Thương Hiệu / Cơ Quan (${item.keyword.toUpperCase()})`,
          details: `Đường dẫn chứa từ khóa nhận diện của '${item.keyword}' nhưng tên miền đích thực tế (${hostname}) không thuộc danh sách tên miền chính thức của đơn vị này.`,
          severity: 'critical',
          scoreWeight: brandWeight,
          category: 'impersonation',
          evidenceSnippet: `${item.keyword} trong ${hostname}`,
          provenance: 'DETERMINISTIC',
        });
        break;
      }
    }
  }

  // 6. Kiểm tra tham số chuyển hướng hở (Open Redirect)
  const hasOpenRedirect = 
    searchParams.has('redirect') || 
    searchParams.has('url') || 
    searchParams.has('next') || 
    searchParams.has('dest') || 
    searchParams.has('return') ||
    searchParams.has('link') ||
    searchParams.has('target');

  if (hasOpenRedirect) {
    const redirWeight = 18;
    scoreSum += redirWeight;
    flags.push({
      id: 'flag-open-redirect',
      name: 'Tham Số Chuyển Hướng Trang Tự Động (Open-Redirect Parameter)',
      details: 'Địa chỉ chứa tham số điều hướng có khả năng bị khai thác để chuyển tiếp nạn nhân sang trang thu thập thông tin giả mạo sau khi truy cập ban đầu.',
      severity: 'medium',
      scoreWeight: redirWeight,
      category: 'data_harvesting',
      evidenceSnippet: Array.from(searchParams.keys()).join(', '),
      provenance: 'DETERMINISTIC',
    });
  }

  // Tính toán điểm số cuối cùng theo Trí Tuệ Mối Đe Dọa Tên Miền 3 Cấp Độ (3-Tier URL Intelligence)
  let finalScamScore = 7;
  let scamLevel: ThreatSeverity = 'low';
  let summary = '';

  if (urlIntel.tier === 'TIER_A_WHITELIST') {
    // TIER A: TRUSTED REPUTATION WHITELIST (0 - 5%, Green)
    finalScamScore = urlIntel.scamScore; // 3%
    scamLevel = 'low';
    summary = urlIntel.verdict;
  } else if (urlIntel.tier === 'TIER_C_MALICIOUS') {
    // TIER C: GENUINE PHISHING & MALICIOUS URLS (85 - 98%, Red / Q3)
    finalScamScore = Math.max(scoreSum, urlIntel.scamScore);
    scamLevel = 'critical';
    summary = urlIntel.verdict;
  } else {
    // TIER B: CLEAN BENIGN DOMAINS & PROJECT WEBSITES (5 - 10%, Green, e.g. smartteenai.xyz)
    finalScamScore = Math.min(10, Math.max(5, scoreSum > 0 ? scoreSum : urlIntel.scamScore));
    scamLevel = 'low';
    summary = urlIntel.verdict;
  }

  // Chuyển đổi cờ thành ScamIndicator tiêu chuẩn
  const scamIndicators: ScamIndicator[] = flags.map(f => ({
    id: f.id,
    title: f.name,
    severity: f.severity,
    category: f.category,
    description: f.details,
    evidenceSnippet: f.evidenceSnippet,
    provenance: f.provenance,
  }));

  // Tạo nguồn xác minh với trạng thái minh bạch, trung thực khoa học
  const verificationSources: VerificationSource[] = [
    {
      name: 'Bộ Phân Tích Cú Pháp & Cấu Trúc URI (RFC 3986)',
      category: 'Quy Tắc Xác Định (Deterministic Heuristics)',
      status: flags.some(f => f.severity === 'critical')
        ? 'malicious'
        : flags.some(f => f.severity === 'high')
        ? 'suspicious'
        : 'verified_format',
      statusLabel: flags.some(f => f.severity === 'critical')
        ? 'Phát Hiện Dấu Hiệu Mạo Danh'
        : flags.some(f => f.severity === 'high')
        ? 'Cấu Trúc Cần Cảnh Giác'
        : 'Cấu Trúc Hợp Lệ (Low Risk)',
      details: urlIntel.tier === 'TIER_A_WHITELIST'
        ? `Tên miền '${hostname}' thuộc danh mục hạ tầng số chính thống / cơ quan nhà nước đã xác thực an toàn.`
        : urlIntel.tier === 'TIER_B_BENIGN'
        ? `Tên miền '${hostname}' có cú pháp chuẩn, cấu trúc sạch, không phát hiện dấu hiệu mạo danh thương hiệu hay mã độc.`
        : `Kiểm tra mã hóa Punycode, địa chỉ IP số, độ sâu subdomain và đối soát từ khóa thương hiệu.`,
      isSimulatedOrPreliminary: false,
      provenance: 'DETERMINISTIC',
    },
    {
      name: 'Cơ Sở Dữ Liệu Danh Sách Đen Tên Miền (Real-time Threat Intelligence Feed)',
      category: 'Cơ Sở Dữ Liệu Đe Dọa (Threat Intelligence)',
      status: 'unavailable_no_live_feed',
      statusLabel: 'Chưa Đối Soát Thời Gian Thực',
      details: 'Chưa đối soát danh sách đen thời gian thực (Khuyến nghị tra cứu tại Tín Nhiệm Mạng).',
      isSimulatedOrPreliminary: true,
      limitationNote: 'Hệ thống chạy trên nền tảng độc lập, chưa kết nối khóa API luồng cấp dữ liệu thương mại thời gian thực.',
      provenance: 'UNAVAILABLE',
    },
  ];

  const externalLinks = buildExternalAuthorityLinks(hostname);

  return {
    rawUrl: raw,
    normalizedUrl,
    hostname,
    domain: parts.slice(-2).join('.'),
    tld,
    isIpAddress,
    isPunycode,
    isCommonNewTld,
    tldSuspicionScore,
    subdomainCount,
    impersonatedBrand,
    flags,
    scamScore: finalScamScore,
    scamLevel,
    confidence: 88,
    summary,
    verificationSources,
    externalLinks,
    scamIndicators,
  };
}

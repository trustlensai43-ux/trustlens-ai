import crypto from 'crypto';
import { evaluateUrlThreatIntelligence } from './threatScoringEngine';

export interface TelemetryAggregationInput {
  modality: 'text' | 'email' | 'phone' | 'url' | 'image' | 'video';
  rawContent: string;
  sender?: string;
  subject?: string;
  phoneNumber?: string;
  callerId?: string;
  url?: string;
  clientBreachData?: {
    leakCount?: number;
    status?: string;
    source?: string;
    note?: string;
  };
}

export interface ExternalBreachTelemetry {
  source: string;
  status: string;
  note: string;
  pwnedCount?: number;
  emailOrTarget?: string;
  sha1Prefix?: string;
}

export interface UrlStructuralTelemetry {
  homoglyph: 'DETECTED' | 'NOT_DETECTED';
  punycode: 'DETECTED' | 'NOT_DETECTED';
  port: string;
  subdomainStacking: string;
  tldRisk: 'HIGH' | 'MODERATE' | 'LOW' | 'BENIGN';
  brandImpersonation?: string;
  targetDomain?: string;
}

export interface PiiTelemetry {
  detectedCccd: 'PRESENT' | 'NONE';
  cccdCount: number;
  detectedBankAccount: 'PRESENT' | 'NONE';
  detectedCards: 'PRESENT' | 'NONE';
  urgencyLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'NONE';
  phoneCarrier?: string;
  carrierPrefix?: string;
}

export interface NationalTrustmarkTelemetry {
  registry: string;
  status: 'CERTIFIED_GOVERNMENT_ORGANIZATION' | 'VERIFIED_BANKING_FINTECH' | 'SUSPECTED_PHISHING_DOMAIN' | 'UNVERIFIED_THIRD_PARTY_DOMAIN' | 'NOT_APPLICABLE';
  note: string;
  matchedBrandOrEntity?: string;
}

export interface AggregatedThreatTelemetry {
  xmlEnvelope: string;
  externalBreachData: ExternalBreachTelemetry;
  urlStructuralHeuristics: UrlStructuralTelemetry;
  piiIndicators: PiiTelemetry;
  nationalTrustmarkContext: NationalTrustmarkTelemetry;
  timestamp: string;
}

// Known official domains for Vietnam government, banking, and major services
const OFFICIAL_VN_DOMAINS = [
  // Government
  '.gov.vn',
  'vneid.gov.vn',
  'dancuquocgia.gov.vn',
  'dichvucong.gov.vn',
  'gdt.gov.vn',
  'bocongan.gov.vn',
  'chinhphu.vn',
  // Banking & Fintech
  'vietcombank.com.vn',
  'vietcombank.com',
  'techcombank.com.vn',
  'techcombank.com',
  'mbbank.com.vn',
  'vietinbank.vn',
  'bidv.com.vn',
  'agribank.com.vn',
  'vpbank.com.vn',
  'acb.com.vn',
  'tpb.vn',
  'tpbank.com.vn',
  'sacombank.com.vn',
  'sacombank.com',
  'momo.vn',
  'vnpay.vn',
  'zalo.me',
  'zalopay.vn',
  // Big Tech / Commerce
  'shopee.vn',
  'shopee.com',
  'lazada.vn',
  'lazada.com',
  'tiktok.com',
  'google.com',
  'apple.com',
  'microsoft.com',
];

// High-risk brand keywords to detect phishing imitation
const BRAND_KEYWORD_IMPERSONATION = [
  'vietcombank',
  'techcombank',
  'mbbank',
  'vietinbank',
  'bidv',
  'agribank',
  'vpbank',
  'acb',
  'tpbank',
  'sacombank',
  'vneid',
  'dichvucong',
  'gdt.gov',
  'tongcucthue',
  'bocongan',
  'shopee',
  'lazada',
  'tiktok',
  'zalo',
  'momo',
  'vnpay',
  'paypal',
  'apple',
  'microsoft',
  'chase',
];

// Cyrillic and lookalike characters used in homoglyph attacks
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic small a
  '\u0435': 'e', // Cyrillic small e
  '\u043E': 'o', // Cyrillic small o
  '\u0440': 'p', // Cyrillic small p
  '\u0441': 'c', // Cyrillic small c
  '\u0443': 'y', // Cyrillic small y
  '\u0445': 'x', // Cyrillic small x
  '\u0456': 'i', // Cyrillic small i
  '\u04CF': 'l', // Cyrillic small palochka
};

// Carrier prefix mapping for Vietnamese telecom providers
function classifyVietnameseCarrier(phoneNum: string): { carrier: string; prefix: string } {
  const clean = phoneNum.replace(/[\s\-\(\)\.]/g, '');
  let normalized = clean;
  if (normalized.startsWith('+84')) {
    normalized = '0' + normalized.slice(3);
  } else if (normalized.startsWith('84')) {
    normalized = '0' + normalized.slice(2);
  }

  // International / Wangiri check
  if (clean.startsWith('+') && !clean.startsWith('+84')) {
    const intlPrefix = clean.slice(0, 4);
    return {
      carrier: 'Đầu Số Quốc Tế Nghi Vấn (Nguy cơ lừa đảo Wangiri / Thu cước cao)',
      prefix: intlPrefix,
    };
  }

  const p3 = normalized.slice(0, 3);
  const p4 = normalized.slice(0, 4);

  // Viettel
  const viettel3 = ['086', '096', '097', '098', '032', '033', '034', '035', '036', '037', '038', '039'];
  if (viettel3.includes(p3)) return { carrier: 'Viettel Telecom', prefix: p3 };

  // Mobifone
  const mobi3 = ['089', '090', '093', '070', '076', '077', '078', '079'];
  if (mobi3.includes(p3)) return { carrier: 'Mobifone Telecom', prefix: p3 };

  // Vinaphone
  const vina3 = ['088', '091', '094', '081', '082', '083', '084', '085'];
  if (vina3.includes(p3)) return { carrier: 'Vinaphone (VNPT)', prefix: p3 };

  // Vietnamobile
  const vnm3 = ['092', '056', '058', '052'];
  if (vnm3.includes(p3)) return { carrier: 'Vietnamobile', prefix: p3 };

  // Gmobile
  const gmo3 = ['099', '059'];
  if (gmo3.includes(p3)) return { carrier: 'Gmobile (Gtel)', prefix: p3 };

  // Itelecom / Wintel
  if (p3 === '087') return { carrier: 'Itelecom (MVNO)', prefix: p3 };
  if (p3 === '055') return { carrier: 'Wintel (Mobicast MVNO)', prefix: p3 };

  // Landline
  if (p3 === '024') return { carrier: 'Mạng Cố Định Hà Nội (VNPT/Viettel)', prefix: p3 };
  if (p3 === '028') return { carrier: 'Mạng Cố Định TP. Hồ Chí Minh', prefix: p3 };
  if (p3.startsWith('02')) return { carrier: 'Mạng Điện Thoại Cố Định Tỉnh', prefix: p3 };

  // Toll-free / Service hotline
  if (p4 === '1900' || p4 === '1800') return { carrier: 'Đầu Số Tổng Đài Dịch Vụ Thu Phí (1900/1800)', prefix: p4 };

  return { carrier: 'Không xác định / Thuê bao mạng ảo hoặc số nội bộ', prefix: p3 || 'N/A' };
}

/**
 * Perform pre-flight telemetry aggregation before Gemini AI invocation.
 */
export async function aggregateThreatTelemetry(
  input: TelemetryAggregationInput
): Promise<AggregatedThreatTelemetry> {
  const { modality, rawContent, sender, phoneNumber, url } = input;
  const combinedText = `${sender || ''} ${subjectOrEmpty(input.subject)} ${rawContent || ''} ${phoneNumber || ''} ${url || ''}`;

  // 1. EXTERNAL BREACH DATA (Have I Been Pwned k-Anonymity)
  let externalBreachData: ExternalBreachTelemetry = {
    source: 'HaveIBeenPwned',
    status: 'NOT_APPLICABLE',
    note: 'Không phát hiện trường định danh tài khoản để đối soát rò rỉ cơ sở dữ liệu mở.',
  };

  if (input.clientBreachData && input.clientBreachData.status) {
    externalBreachData = {
      source: input.clientBreachData.source || 'HaveIBeenPwned',
      status: input.clientBreachData.status,
      note: input.clientBreachData.note || 'Dữ liệu đối soát k-Anonymity từ phiên kiểm tra của người dùng.',
      pwnedCount: input.clientBreachData.leakCount,
    };
  } else {
    // Check if an email or credential exists in input
    const emailMatch = combinedText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/);
    const targetEmail = (sender && sender.includes('@')) ? sender.trim() : (emailMatch ? emailMatch[0].trim() : null);

    if (targetEmail) {
      try {
        const cleanEmail = targetEmail.toLowerCase();
        const sha1 = crypto.createHash('sha1').update(cleanEmail).digest('hex').toUpperCase();
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);

        // Fetch range with 2-second timeout to avoid latency bottlenecks
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);

        const upstreamRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
          signal: controller.signal,
          headers: {
            'User-Agent': 'TrustLensAI-TelemetrySynthesizer/2.0',
            'Add-Padding': 'true',
          },
        });
        clearTimeout(timeoutId);

        if (upstreamRes.ok) {
          const body = await upstreamRes.text();
          const lines = body.split('\n');
          let matchCount = 0;
          for (const line of lines) {
            const [entrySuffix, countStr] = line.trim().split(':');
            if (entrySuffix && entrySuffix.toUpperCase() === suffix) {
              matchCount = parseInt(countStr, 10) || 1;
              break;
            }
          }

          if (matchCount > 0) {
            externalBreachData = {
              source: 'HaveIBeenPwned',
              status: `PWNED_${matchCount}_BREACH`,
              note: `Email/dữ liệu xác thực đã xuất hiện ${matchCount} lần trong các cơ sở dữ liệu rò rỉ công khai đã được xác minh.`,
              pwnedCount: matchCount,
              emailOrTarget: cleanEmail,
              sha1Prefix: prefix,
            };
          } else {
            externalBreachData = {
              source: 'HaveIBeenPwned',
              status: 'NO_KNOWN_BREACH',
              note: 'Chưa phát hiện rò rỉ trong cơ sở dữ liệu công khai đã lập chỉ mục (k-Anonymity Verified).',
              pwnedCount: 0,
              emailOrTarget: cleanEmail,
              sha1Prefix: prefix,
            };
          }
        } else {
          externalBreachData = {
            source: 'HaveIBeenPwned',
            status: 'UNAVAILABLE_OFFLINE',
            note: 'Máy chủ Have I Been Pwned phản hồi mã lỗi hoặc đang giới hạn tần suất.',
            emailOrTarget: cleanEmail,
          };
        }
      } catch (fetchErr: any) {
        externalBreachData = {
          source: 'HaveIBeenPwned',
          status: 'UNAVAILABLE_OFFLINE',
          note: 'Không thể kết nối đến máy chủ Have I Been Pwned trong thời gian cho phép (timeout).',
        };
      }
    }
  }

  // 2. URL STRUCTURAL HEURISTICS & 3. NATIONAL TRUSTMARK CONTEXT
  let urlStructuralHeuristics: UrlStructuralTelemetry = {
    homoglyph: 'NOT_DETECTED',
    punycode: 'NOT_DETECTED',
    port: 'STANDARD',
    subdomainStacking: 'NORMAL',
    tldRisk: 'LOW',
  };

  let nationalTrustmarkContext: NationalTrustmarkTelemetry = {
    registry: 'Tín Nhiệm Mạng / NCSC',
    status: 'NOT_APPLICABLE',
    note: 'Không phát hiện địa chỉ liên kết web (URL) trong nội dung để đối soát chứng nhận.',
  };

  // Find URL candidate in input
  const urlRegex = /(https?:\/\/[^\s<>"']+)|(\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|vn|edu\.vn|gov\.vn|top|xyz|online|site|work|click|loan|fit|cc|me|vip|icu|buzz)(?:\/[^\s<>"']*)?)/gi;
  const urlMatches = combinedText.match(urlRegex);
  const targetUrl = url || (urlMatches ? urlMatches[0] : null);

  if (targetUrl) {
    try {
      const raw = targetUrl.trim();
      const parsed = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
      const hostname = parsed.hostname.toLowerCase();
      const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');

      // Check Punycode / Homoglyph
      const isPunycode = hostname.includes('xn--');
      let isHomoglyph = isPunycode;
      for (const [char] of Object.entries(HOMOGLYPH_MAP)) {
        if (hostname.includes(char)) {
          isHomoglyph = true;
          break;
        }
      }

      // Check port anomalies
      const isPortAnomalous = port !== '80' && port !== '443';

      // Check Subdomain Stacking
      const parts = hostname.split('.');
      const hasStacking = parts.length > 3;

      // 3-Tier URL Threat Intelligence evaluation
      const urlIntel = evaluateUrlThreatIntelligence(raw);

      let tldRisk: 'HIGH' | 'MODERATE' | 'LOW' | 'BENIGN' = 'BENIGN';
      if (urlIntel.tier === 'TIER_C_MALICIOUS') {
        tldRisk = 'HIGH';
      } else if (urlIntel.tier === 'TIER_A_WHITELIST') {
        tldRisk = 'BENIGN';
      } else {
        // TIER B (e.g. smartteenai.xyz) is BENIGN / LOW risk
        tldRisk = 'BENIGN';
      }

      // Check Brand Impersonation against Vietnamese official list
      let impersonatedBrand: string | undefined = urlIntel.impersonatedBrand;
      if (!impersonatedBrand) {
        for (const brand of BRAND_KEYWORD_IMPERSONATION) {
          if (hostname.includes(brand)) {
            const isOfficial = OFFICIAL_VN_DOMAINS.some(off => hostname === off || hostname.endsWith('.' + off));
            if (!isOfficial) {
              impersonatedBrand = brand.toUpperCase();
              break;
            }
          }
        }
      }

      urlStructuralHeuristics = {
        homoglyph: isHomoglyph ? 'DETECTED' : 'NOT_DETECTED',
        punycode: isPunycode ? 'DETECTED' : 'NOT_DETECTED',
        port: isPortAnomalous ? port : 'STANDARD',
        subdomainStacking: hasStacking ? `STACKING_DETECTED (levels=${parts.length})` : 'NORMAL',
        tldRisk,
        brandImpersonation: impersonatedBrand,
        targetDomain: hostname,
      };

      // National Trustmark (Tín Nhiệm Mạng & Chống Lừa Đảo heuristics)
      if (urlIntel.tier === 'TIER_A_WHITELIST' || hostname.endsWith('.gov.vn')) {
        nationalTrustmarkContext = {
          registry: 'Tín Nhiệm Mạng / NCSC',
          status: 'CERTIFIED_GOVERNMENT_ORGANIZATION',
          note: `Tên miền '${hostname}' thuộc danh mục hạ tầng số chính thống / tổ chức uy tín đã được xác thực an toàn.`,
          matchedBrandOrEntity: 'Tổ chức Uy tín / Cơ quan Nhà nước',
        };
      } else if (OFFICIAL_VN_DOMAINS.some(off => hostname === off || hostname.endsWith('.' + off))) {
        nationalTrustmarkContext = {
          registry: 'Tín Nhiệm Mạng / NCSC',
          status: 'VERIFIED_BANKING_FINTECH',
          note: `Tên miền '${hostname}' trùng khớp với cơ sở dữ liệu hạ tầng chính thức của tổ chức tài chính / dịch vụ được cấp phép.`,
          matchedBrandOrEntity: impersonatedBrand || hostname,
        };
      } else if (urlIntel.tier === 'TIER_C_MALICIOUS' || impersonatedBrand) {
        nationalTrustmarkContext = {
          registry: 'Tín Nhiệm Mạng / NCSC',
          status: 'SUSPECTED_PHISHING_DOMAIN',
          note: `Tên miền '${hostname}' chứa dấu hiệu giả mạo (${impersonatedBrand || 'Mã độc/Phishing'}), vi phạm tiêu chuẩn an toàn NCSC.`,
          matchedBrandOrEntity: impersonatedBrand || hostname,
        };
      } else {
        // TIER B: Clean benign domains & project websites
        nationalTrustmarkContext = {
          registry: 'Tín Nhiệm Mạng / NCSC',
          status: 'UNVERIFIED_THIRD_PARTY_DOMAIN',
          note: `Tên miền '${hostname}' là trang web sạch, không ghi nhận dấu hiệu giả mạo thương hiệu hay mã độc (Đánh giá mức độ rủi ro thấp 5-10%).`,
          matchedBrandOrEntity: hostname,
        };
      }
    } catch {
      urlStructuralHeuristics = {
        homoglyph: 'NOT_DETECTED',
        punycode: 'NOT_DETECTED',
        port: 'INVALID_URI',
        subdomainStacking: 'PARSE_ERROR',
        tldRisk: 'MODERATE',
      };
      nationalTrustmarkContext = {
        registry: 'Tín Nhiệm Mạng / NCSC',
        status: 'UNVERIFIED_THIRD_PARTY_DOMAIN',
        note: 'Cú pháp URL không hợp lệ theo tiêu chuẩn RFC 3986.',
      };
    }
  }

  // 4. PII INDICATORS & CARRIER CLASSIFICATION
  const cccdMatches = combinedText.match(/\b0\d{11}\b/g);
  const detectedCccd = cccdMatches && cccdMatches.length > 0 ? 'PRESENT' : 'NONE';
  const cccdCount = cccdMatches ? cccdMatches.length : 0;

  const bankRegex = /(?:stk|tk|số\s+tài\s+khoản|tài\s+khoản|account|acc|bank|ngân\s+hàng)[:\s]*([0-9]{8,16})\b/gi;
  const detectedBank = bankRegex.test(combinedText) ? 'PRESENT' : 'NONE';

  const cardRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
  const detectedCards = cardRegex.test(combinedText) ? 'PRESENT' : 'NONE';

  // Urgency & Coercion triggers
  const textLower = combinedText.toLowerCase();
  const criticalUrgencyTriggers = [
    'lệnh bắt', 'viện kiểm sát', 'bộ công an', 'công an điều tra', 'khởi tố',
    'phạt nguội', 'đóng băng tài khoản', 'mã otp', 'tuyệt đối không chia sẻ'
  ];
  const highUrgencyTriggers = [
    'khẩn cấp', 'ngay lập tức', 'trong vòng 24h', 'trong vòng 2h', 'khóa tài khoản',
    'nộp phạt', 'chuyển tiền ngay', 'trúng thưởng', 'kích hoạt vneid mức 2', 'nâng cấp sinh trắc học'
  ];
  const moderateUrgencyTriggers = [
    'liên hệ gấp', 'xác minh ngay', 'ưu đãi có hạn', 'làm nhiệm vụ', 'hoa hồng', 'hoàn tiền'
  ];

  let urgencyLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'NONE' = 'NONE';
  if (criticalUrgencyTriggers.some(term => textLower.includes(term))) {
    urgencyLevel = 'CRITICAL';
  } else if (highUrgencyTriggers.some(term => textLower.includes(term))) {
    urgencyLevel = 'HIGH';
  } else if (moderateUrgencyTriggers.some(term => textLower.includes(term))) {
    urgencyLevel = 'MODERATE';
  }

  // Phone Carrier Prefix
  let phoneCarrierInfo: { carrier: string; prefix: string } | undefined = undefined;
  const phoneTarget = phoneNumber || (combinedText.match(/(?:\+84|84|0)(3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b/g)?.[0]);
  if (phoneTarget) {
    phoneCarrierInfo = classifyVietnameseCarrier(phoneTarget);
  }

  const piiIndicators: PiiTelemetry = {
    detectedCccd,
    cccdCount,
    detectedBankAccount: detectedBank,
    detectedCards,
    urgencyLevel,
    phoneCarrier: phoneCarrierInfo?.carrier,
    carrierPrefix: phoneCarrierInfo?.prefix,
  };

  // Build the XML Envelope strictly adhering to the Multi-Source Threat Intelligence Synthesizer schema
  const xmlEnvelope = `<threat_telemetry>
  <target_type>${input.modality.toUpperCase()}</target_type>
  <external_breach_data source="${externalBreachData.source}" status="${externalBreachData.status}" pwned_count="${externalBreachData.pwnedCount ?? 0}" note="${escapeXml(externalBreachData.note)}"/>
  <url_structural_heuristics homoglyph="${urlStructuralHeuristics.homoglyph}" punycode="${urlStructuralHeuristics.punycode}" port="${urlStructuralHeuristics.port}" subdomain_stacking="${escapeXml(urlStructuralHeuristics.subdomainStacking)}" tld_risk="${urlStructuralHeuristics.tldRisk}" brand_impersonation="${escapeXml(urlStructuralHeuristics.brandImpersonation || 'NONE')}" target_domain="${escapeXml(urlStructuralHeuristics.targetDomain || 'NONE')}"/>
  <pii_indicators detected_cccd="${piiIndicators.detectedCccd}" cccd_count="${piiIndicators.cccdCount}" detected_bank_account="${piiIndicators.detectedBankAccount}" detected_cards="${piiIndicators.detectedCards}" urgency_level="${piiIndicators.urgencyLevel}" phone_carrier="${escapeXml(piiIndicators.phoneCarrier || 'NONE')}"/>
  <national_trustmark_context registry="${nationalTrustmarkContext.registry}" status="${nationalTrustmarkContext.status}" note="${escapeXml(nationalTrustmarkContext.note)}" matched_entity="${escapeXml(nationalTrustmarkContext.matchedBrandOrEntity || 'NONE')}"/>
</threat_telemetry>`;

  return {
    xmlEnvelope,
    externalBreachData,
    urlStructuralHeuristics,
    piiIndicators,
    nationalTrustmarkContext,
    timestamp: new Date().toISOString(),
  };
}

function escapeXml(str: string): string {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function subjectOrEmpty(subject?: string): string {
  return subject ? `[Tiêu đề: ${subject}]` : '';
}

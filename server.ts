import express, { Request, Response } from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';
import { inspectUrl } from './src/utils/urlInspector';
import { aggregateThreatTelemetry, AggregatedThreatTelemetry } from './src/utils/telemetryAggregator';
import { analyzeLocally } from './src/utils/localHeuristicEngine';
import { evaluateUrlThreatIntelligence } from './src/utils/threatScoringEngine';

dotenv.config();

const app = express();
const PORT = 3000;

// Middleware for body parsing
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Lazy initialize Gemini client
function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.warn('GEMINI_API_KEY is not set in environment. Running in offline deterministic heuristic mode.');
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// Simple in-memory rate limiter per IP
const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 60; // 60 requests per minute
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

function rateLimiter(req: Request, res: Response, next: () => void) {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const clientData = requestCounts.get(clientIp);

  if (!clientData || now > clientData.resetTime) {
    requestCounts.set(clientIp, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (clientData.count >= RATE_LIMIT_MAX) {
    return res.status(429).json({
      error: 'Rate limit exceeded. Please wait a moment before running more analyses.',
    });
  }

  clientData.count++;
  next();
}

// Health check endpoint
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'TrustLens AI Analysis Pipeline',
    version: '1.4.0',
    geminiConfigured: !!process.env.GEMINI_API_KEY,
  });
});

// PII Sanitization Helper (Đã nâng cấp hỗ trợ định dạng dữ liệu Việt Nam)
function sanitizePiiText(text: string, options: { preserveTargetPhone?: boolean } = {}): string {
  if (!text) return '';
  let sanitized = text;

  // 1. Mã OTP 6 chữ số
  sanitized = sanitized.replace(
    /(?:mã(?:\s+xác\s+(?:thực|minh))?|otp|code)[:\s]*([0-9]{6})\b/gi,
    'Mã OTP: [ĐÃ CHE OTP]'
  );
  sanitized = sanitized.replace(
    /\b([0-9]{6})\b(?=\s*(?:là\s+mã|hết\s+hạn|để\s+xác\s+thực|otp))/gi,
    '[ĐÃ CHE OTP]'
  );

  // 2. Thẻ thanh toán (16 chữ số định dạng Visa, Mastercard, Napas)
  sanitized = sanitized.replace(
    /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
    '[ĐÃ CHE SỐ THẺ]'
  );

  // 3. Số tài khoản ngân hàng (8 đến 16 chữ số đi kèm từ khóa ngân hàng)
  sanitized = sanitized.replace(
    /(?:stk|tk|số\s+tài\s+khoản|tài\s+khoản|account|acc|bank|ngân\s+hàng)[:\s]*([0-9]{8,16})\b/gi,
    'STK: [ĐÃ CHE STK]'
  );

  // 4. Căn cước công dân Việt Nam (CCCD 12 chữ số bắt đầu bằng số 0)
  sanitized = sanitized.replace(
    /\b0\d{11}\b/g,
    '[ĐÃ CHE CCCD]'
  );

  // 5. Địa chỉ Email
  sanitized = sanitized.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    '[ĐÃ CHE EMAIL]'
  );

  // 6. Số điện thoại (nếu không được chỉ định giữ lại để tra cứu viễn thông)
  if (!options.preserveTargetPhone) {
    sanitized = sanitized.replace(
      /(?:\+84|84|0)(3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b/g,
      '[ĐÃ CHE SĐT]'
    );
    sanitized = sanitized.replace(
      /\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b/g,
      '[ĐÃ CHE SĐT]'
    );
  }

  return sanitized;
}

// URL Heuristic parser (Quy tắc xác thực cú pháp & dấu hiệu lừa đảo trên tên miền)
function analyzeUrlHeuristics(targetUrl: string) {
  const flags: { name: string; details: string; severity: 'low' | 'medium' | 'high' | 'critical' }[] = [];
  try {
    const raw = targetUrl.trim();
    const parsed = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
    const hostname = parsed.hostname.toLowerCase();
    
    // Homoglyph / Punycode check
    if (hostname.includes('xn--')) {
      flags.push({
        name: 'Ký tự giả mạo Quốc tế hóa (Punycode / Homoglyph)',
        details: `Tên miền chứa ký tự mã hóa đặc biệt (${hostname}) thường được kẻ lừa đảo dùng để đánh lừa mắt người dùng khi nhìn tên thương hiệu.`,
        severity: 'critical',
      });
    }

    // IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      flags.push({
        name: 'Sử dụng trực tiếp địa chỉ IP thay cho Tên miền',
        details: 'Địa chỉ web sử dụng chuỗi IP số thô thay vì tên miền đã đăng ký hợp lệ, né tránh việc kiểm duyệt uy tín tên miền từ DNS.',
        severity: 'high',
      });
    }

    // Executable dropper check (.apk / .exe)
    if (/\.(apk|exe|dmg|msi|bat|scr|vbs)(\?|$|\s|\/)/i.test(raw)) {
      flags.push({
        name: 'Đường dẫn tải tệp tin thực thi / mã độc Android (.APK, .EXE)',
        details: 'Phát hiện liên kết tải tệp tin ứng dụng ngoài nguy hiểm (.apk/.exe) có nguy cơ chiếm quyền thiết bị.',
        severity: 'critical',
      });
    }

    // 3-Tier URL threat intelligence evaluation
    const urlIntel = evaluateUrlThreatIntelligence(raw);
    if (urlIntel.impersonatedBrand) {
      flags.push({
        name: 'Dấu hiệu mạo danh từ khóa Thương hiệu / Cơ quan',
        details: `Địa chỉ web chứa từ khóa định danh '${urlIntel.impersonatedBrand}' nhưng không trỏ về tên miền gốc chính thức của đơn vị này.`,
        severity: 'critical',
      });
    }

    // Open redirect / tracking parameter tokens
    if (parsed.searchParams.has('redirect') || parsed.searchParams.has('url') || parsed.searchParams.has('next') || parsed.searchParams.has('dest') || parsed.searchParams.has('return')) {
      flags.push({
        name: 'Tham số chuyển hướng trang tự động (Open-Redirect Parameter)',
        details: 'Đường dẫn chứa tham số chuyển tiếp có thể bị lợi dụng để điều hướng nạn nhân từ một trang ban đầu sang máy chủ thu thập mã độc.',
        severity: 'medium',
      });
    }
  } catch {
    flags.push({
      name: 'Cú pháp URL không hợp lệ',
      details: 'Chuỗi ký tự được gửi lên không thể phân tích cú pháp thành một định dạng URI tiêu chuẩn RFC 3986.',
      severity: 'medium',
    });
  }
  return flags;
}

// Pwned Passwords k-Anonymity Range Proxy Endpoint
app.get('/api/pwned-range/:prefix', rateLimiter, async (req: Request, res: Response) => {
  try {
    const { prefix } = req.params;
    if (!prefix || !/^[0-9A-Fa-f]{5}$/.test(prefix)) {
      return res.status(400).json({ error: 'Tiền tố băm k-Anonymity phải gồm đúng 5 ký tự thập lục phân (hex).' });
    }

    const cleanPrefix = prefix.toUpperCase();
    const upstreamRes = await fetch(`https://api.pwnedpasswords.com/range/${cleanPrefix}`, {
      headers: {
        'User-Agent': 'TrustLensAI-BreachIntelligence/2.0',
        'Add-Padding': 'true',
      },
    });

    if (!upstreamRes.ok) {
      return res.status(upstreamRes.status).send(await upstreamRes.text());
    }

    const body = await upstreamRes.text();
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.send(body);
  } catch (err: any) {
    console.warn('Pwned passwords upstream fetch failed:', err?.message);
    return res.status(502).json({
      error: 'Không thể kết nối đến máy chủ Have I Been Pwned. Thiết bị có thể đang ngoại tuyến hoặc kết nối mạng bị chặn.',
    });
  }
});

// Deterministic Offline Fallback for Composite Privacy & PII Exposure Audit
function auditExposureDeterministically(rawText: string) {
  const items: Array<{
    type: string;
    label: string;
    snippet: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    riskReason: string;
  }> = [];

  const textLower = rawText.toLowerCase();

  // 1. Check CCCD
  const cccdMatches = rawText.match(/\b0\d{11}\b/g);
  if (cccdMatches) {
    items.push({
      type: 'cccd',
      label: 'Căn Cước Công Dân (12 chữ số)',
      snippet: cccdMatches[0].slice(0, 3) + '******' + cccdMatches[0].slice(-3),
      severity: 'critical',
      riskReason: 'CCCD là định danh cốt lõi quốc gia; lộ lọt là chìa khóa mở đường cho việc đăng ký SIM rác, mở tài khoản trực tuyến lừa đảo hoặc vay nợ tài chính.',
    });
  }

  // 2. Check Payment Card
  const cardMatches = rawText.match(/\b(?:\d{4}[ -]?){3}\d{4}\b/g);
  if (cardMatches) {
    items.push({
      type: 'card',
      label: 'Số Thẻ Thanh Toán Quốc Tế / Nội Địa',
      snippet: cardMatches[0].slice(0, 4) + ' **** **** ' + cardMatches[0].slice(-4),
      severity: 'critical',
      riskReason: 'Dễ dàng bị lợi dụng để thanh toán trái phép trên các cổng quốc tế không yêu cầu mã OTP (giao dịch 3D-Secure lỏng lẻo).',
    });
  }

  // 3. Check Bank Account
  const bankMatches = rawText.match(/(?:stk|tk|số\s+tài\s+khoản|tài\s+khoản|account|acc|bank|ngân\s+hàng)[:\s]*([0-9]{8,16})\b/gi);
  if (bankMatches) {
    items.push({
      type: 'bank_account',
      label: 'Số Tài Khoản Ngân Hàng',
      snippet: bankMatches[0],
      severity: 'high',
      riskReason: 'Cho phép kẻ xấu kết nối với họ tên để xây dựng kịch bản mạo danh ngân hàng gửi tin nhắn tra soát giao dịch giả mạo.',
    });
  }

  // 4. Check Phone Number
  const phoneMatches = rawText.match(/(?:\+84|84|0)(3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b/g);
  if (phoneMatches) {
    items.push({
      type: 'phone',
      label: 'Số Điện Thoại Di Động',
      snippet: phoneMatches[0].slice(0, 4) + '***' + phoneMatches[0].slice(-3),
      severity: 'medium',
      riskReason: 'Mục tiêu của các đợt phát tán tin nhắn SMS Brandname giả mạo, cuộc gọi dọa khóa thuê bao hoặc nợ cước viễn thông.',
    });
  }

  // 5. Check Email
  const emailMatches = rawText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g);
  if (emailMatches) {
    items.push({
      type: 'email',
      label: 'Địa Chỉ Hòm Thư Điện Tử',
      snippet: emailMatches[0].split('@')[0].slice(0, 3) + '***@' + emailMatches[0].split('@')[1],
      severity: 'low',
      riskReason: 'Đích nhắm của các chiến dịch Phishing mạo danh tài liệu công việc hoặc cảnh báo bảo mật giả mạo từ dịch vụ đám mây.',
    });
  }

  // 6. Check Address Elements
  if (
    textLower.includes('phường ') || 
    textLower.includes('quận ') || 
    textLower.includes('huyện ') || 
    textLower.includes('thành phố ') || 
    textLower.includes('tỉnh ') ||
    textLower.includes('đường ') ||
    textLower.includes('xã ')
  ) {
    items.push({
      type: 'address',
      label: 'Địa Chỉ Cư Trú / Cơ Quan',
      snippet: 'Địa chỉ địa lý chi tiết trong văn bản',
      severity: 'medium',
      riskReason: 'Tăng mức độ thuyết phục khi kẻ xấu mạo danh cán bộ Công an phường/quận gọi điện yêu cầu kích hoạt định danh mức 2.',
    });
  }

  // Calculate composite attack vectors
  const hasCccd = items.some(i => i.type === 'cccd');
  const hasCard = items.some(i => i.type === 'card');
  const hasBank = items.some(i => i.type === 'bank_account');
  const hasPhone = items.some(i => i.type === 'phone');
  const hasAddress = items.some(i => i.type === 'address');

  const attackVectors: Array<{
    vector: string;
    explanation: string;
    severity: 'medium' | 'high' | 'critical';
    targetedThreats: string[];
  }> = [];

  let riskScore = 15;
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

  if (hasCccd && hasPhone) {
    riskScore = Math.max(riskScore, 88);
    riskLevel = 'critical';
    attackVectors.push({
      vector: 'Chiếm Quyền Thuê Bao Di Động (SIM-Swap Attack)',
      explanation: 'Sự kết hợp giữa Số điện thoại và Căn cước công dân (CCCD) tạo điều kiện cho kẻ xấu thực hiện thủ tục giả mạo chủ thuê bao tại điểm giao dịch viễn thông để cấp lại thẻ SIM, cướp đoạt mã OTP đăng nhập ngân hàng và ví điện tử.',
      severity: 'critical',
      targetedThreats: ['Cướp mã OTP SMS', 'Chiếm tài khoản ngân hàng số', 'Chiếm quyền ứng dụng OTT (Zalo, Telegram)'],
    });
  }

  if (hasCccd && (hasAddress || hasPhone)) {
    riskScore = Math.max(riskScore, 85);
    riskLevel = 'critical';
    attackVectors.push({
      vector: 'Mạo Danh Làm Hồ Sơ Tín Dụng & Mở Tài Khoản Ngân Hàng Ảo (eKYC Spoofing)',
      explanation: 'Bộ dữ liệu gồm CCCD kết hợp cùng địa chỉ thường trú và số điện thoại là tập hợp thông tin tiêu chuẩn để vượt qua các lớp xác thực hồ sơ sơ bộ của các ứng dụng cho vay trực tuyến hoặc mở tài khoản ngân hàng ảo rửa tiền.',
      severity: 'critical',
      targetedThreats: ['Nợ xấu tín dụng đen', 'Tài khoản mạo danh phục vụ lừa đảo'],
    });
  }

  if (hasBank && hasPhone) {
    riskScore = Math.max(riskScore, 75);
    if (riskLevel === 'low') riskLevel = 'high';
    attackVectors.push({
      vector: 'Tấn Công Kỹ Nghệ Xã Hội Định Hướng (Spear-Phishing & Vishing)',
      explanation: 'Biết rõ số tài khoản ngân hàng và số điện thoại cho phép kẻ gian đóng vai nhân viên chăm sóc khách hàng gọi điện thông báo "biến động số dư bất thường", dẫn dụ người dùng truy cập trang web mạo danh để chiếm đoạt tài khoản.',
      severity: 'high',
      targetedThreats: ['Mạo danh tổng đài viên ngân hàng', 'Dụ cài ứng dụng độc hại giả mạo'],
    });
  }

  if (hasCard) {
    riskScore = Math.max(riskScore, 92);
    riskLevel = 'critical';
    attackVectors.push({
      vector: 'Gian Lận Giao Dịch Thẻ Không Cần Mã PIN (CNP - Card Not Present)',
      explanation: 'Lộ số thẻ thanh toán quốc tế tiềm ẩn rủi ro phát sinh các khoản trừ tiền tự động từ các dịch vụ thanh toán nước ngoài không kích hoạt xác thực hai yếu tố 3D-Secure.',
      severity: 'critical',
      targetedThreats: ['Quẹt thẻ gian lận', 'Rút cạn hạn mức tín dụng'],
    });
  }

  if (items.length === 0) {
    riskScore = 8;
    riskLevel = 'low';
  } else if (attackVectors.length === 0) {
    riskScore = Math.min(45, items.length * 18);
    riskLevel = riskScore > 30 ? 'medium' : 'low';
    attackVectors.push({
      vector: 'Thu Thập Dữ Liệu Rời Rạc (Passive OSINT Reconnaissance)',
      explanation: 'Dữ liệu chỉ bao gồm các thành phần đơn lẻ, chưa đủ để hình thành véc-tơ tấn công danh tính phức tạp ngay lập tức, nhưng vẫn có thể bị các công cụ OSINT thu thập để tích lũy hồ sơ dài hạn.',
      severity: 'medium',
      targetedThreats: ['Spam quảng cáo', 'Phát tán email rác'],
    });
  }

  const recommendations = [
    hasCccd ? 'Che mờ 6 chữ số giữa của CCCD trước khi chia sẻ ảnh chụp tài liệu trên mạng xã hội.' : null,
    hasBank ? 'Chỉ cung cấp số tài khoản trong môi trường giao dịch trực tiếp, không đính kèm thông tin cá nhân mở rộng.' : null,
    hasPhone ? 'Kích hoạt tính năng chặn cuộc gọi rác và không sử dụng SĐT chính chủ công khai cho các dịch vụ bảo mật ngân hàng nếu có thể.' : null,
    'Kiểm tra định kỳ lịch sử tra cứu thông tin tín dụng CIC cá nhân để phát hiện sớm các khoản vay bất thường.',
  ].filter(Boolean) as string[];

  return {
    riskScore,
    riskLevel,
    detectedPiiItems: items,
    compositeAttackVectors: attackVectors,
    recommendations,
    provenance: 'AI_HEURISTIC' as const,
    summary: `Phát hiện ${items.length} phần tử định danh nhạy cảm. ${
      riskScore >= 75
        ? 'Mức độ rủi ro lộ lọt tổng hợp RẤT CAO do sự kết hợp của các trường dữ liệu định danh cốt lõi có thể tạo điều kiện cho các cuộc tấn công chiếm quyền tài khoản hoặc mạo danh tín dụng.'
        : riskScore >= 40
        ? 'Mức độ rủi ro trung bình. Cần cẩn trọng rà soát che giấu các trường thông tin nhạy cảm trước khi công khai.'
        : 'Nội dung chứa ít hoặc không chứa các thành phần dữ liệu nhạy cảm nguy hiểm.'
    }`,
    timestamp: new Date().toISOString(),
  };
}

// Endpoint: Passive Text/Note Privacy & Composite Exposure Auditor
app.post('/api/audit-exposure', rateLimiter, async (req: Request, res: Response) => {
  try {
    const { text, context } = req.body;
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'Nội dung văn bản cần kiểm tra không được để trống.' });
    }

    const ai = getGeminiClient();
    if (!ai) {
      const fallbackResult = auditExposureDeterministically(text);
      return res.json(fallbackResult);
    }

    const prompt = `Bạn là một Chuyên Gia An Ninh Thông Tin & Bảo Mật Quyền Riêng Tư Cấp Cao (Principal Cybersecurity & Privacy Architect).
Nhiệm vụ của bạn là đánh giá "Mức độ rủi ro lộ lọt danh tính tổng hợp" (Composite Privacy Risk) cho một đoạn văn bản hoặc nội dung người dùng dự định chia sẻ/gửi đi.

NGUYÊN TẮC PHÂN TÍCH:
1. Đánh giá tính nguy hiểm của SỰ KẾT HỢP (Composite Risk) các trường dữ liệu PII:
   - Một trường dữ liệu riêng lẻ (như Họ tên hoặc SĐT) có thể ít nguy hiểm, nhưng khi KẾT HỢP (VD: CCCD + Họ tên + Địa chỉ thường trú + Ngân hàng) sẽ tạo thành véc-tơ tấn công danh tính toàn diện:
     + Tấn công SIM-Swap (Chiếm quyền số điện thoại qua nhà mạng viễn thông)
     + Mạo danh eKYC mở tài khoản ngân hàng ảo / Đăng ký khoản vay tín dụng đen
     + Tấn công Kỹ nghệ xã hội tinh vi (Spear Phishing / Vishing mạo danh cơ quan công an / ngân hàng)
     + Chiếm đoạt tài khoản trực tuyến (Credential Takeover)
2. Thấu hiểu sâu sắc bối cảnh dữ liệu và hạ tầng Việt Nam: CCCD 12 số, SIM rác, ứng dụng VNeID, Mobile Banking, Cổng Dịch vụ công, các ngân hàng thương mại phổ biến (Vietcombank, Techcombank, MB, BIDV,...).
3. Đánh giá khách quan, trung thực khoa học, tuyệt đối không suy đoán vô căn cứ hoặc bịa đặt dữ liệu rò rỉ khi không có căn cứ.
4. Toàn bộ ngôn ngữ giải thích, khuyến nghị phải bằng TIẾNG VIỆT tự nhiên, chuẩn mực, mang tính chuyên môn cao.

NỘI DUNG VĂN BẢN CẦN KIỂM TRA:
<untrusted_content>
${text.slice(0, 8000)}
</untrusted_content>
${context ? `Ngữ cảnh bổ sung: ${context}` : ''}`;

    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.7-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              riskScore: { type: Type.NUMBER, description: 'Điểm rủi ro tổng hợp 0 đến 100' },
              riskLevel: { type: Type.STRING, description: 'low, medium, high, hoặc critical' },
              summary: { type: Type.STRING, description: 'Tóm tắt tổng quan về rủi ro lộ lọt danh tính' },
              detectedPiiItems: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: { type: Type.STRING },
                    label: { type: Type.STRING },
                    snippet: { type: Type.STRING },
                    severity: { type: Type.STRING, description: 'low, medium, high, critical' },
                    riskReason: { type: Type.STRING },
                  },
                  required: ['type', 'label', 'snippet', 'severity', 'riskReason'],
                },
              },
              compositeAttackVectors: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    vector: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                    severity: { type: Type.STRING, description: 'medium, high, critical' },
                    targetedThreats: { type: Type.ARRAY, items: { type: Type.STRING } },
                  },
                  required: ['vector', 'explanation', 'severity', 'targetedThreats'],
                },
              },
              recommendations: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
            },
            required: ['riskScore', 'riskLevel', 'summary', 'detectedPiiItems', 'compositeAttackVectors', 'recommendations'],
          },
        },
      });

      const parsed = JSON.parse(response.text || '{}');
      return res.json({
        ...parsed,
        provenance: 'AI_HEURISTIC',
        timestamp: new Date().toISOString(),
      });
    } catch (modelErr: any) {
      console.warn('Gemini exposure audit failed, falling back to deterministic engine:', modelErr?.message);
      const fallbackResult = auditExposureDeterministically(text);
      return res.json(fallbackResult);
    }
  } catch (err: any) {
    console.error('Audit exposure endpoint failed:', err);
    return res.status(500).json({ error: 'Đã xảy ra lỗi trong quá trình phân tích rủi ro lộ lọt dữ liệu.' });
  }
});

// Main Analysis Endpoint
app.post('/api/analyze', rateLimiter, async (req: Request, res: Response) => {
  try {
    const {
      modality,
      text,
      sender,
      subject,
      phoneNumber,
      callerId,
      transcript,
      url,
      imageDataBase64,
      imageMimeType,
      videoTranscript,
      videoFramesBase64,
      options = {},
    } = req.body;

    if (!modality) {
      return res.status(400).json({ error: 'Tham số loại hình dữ liệu (modality) là bắt buộc.' });
    }

    const redactPii = options.redactPii === true;

    // Build context description tailored specifically to modality
    let combinedInputText = '';
    const inputMetadata: Record<string, any> = {};

    if (modality === 'text') {
      combinedInputText = text || '';
      if (redactPii) combinedInputText = sanitizePiiText(combinedInputText);
      inputMetadata.rawLength = combinedInputText.length;
    } else if (modality === 'email') {
      const cleanSender = redactPii ? sanitizePiiText(sender || '') : (sender || '');
      const cleanSubject = redactPii ? sanitizePiiText(subject || '') : (subject || '');
      const cleanBody = redactPii ? sanitizePiiText(text || '') : (text || '');
      combinedInputText = `[THƯ ĐIỆN TỬ / EMAIL HEADERS & NỘI DUNG]\nNgười gửi (From): ${cleanSender || 'Không cung cấp'}\nTiêu đề (Subject): ${cleanSubject || 'Không cung cấp'}\nNội dung thư:\n${cleanBody}`;
      inputMetadata.sender = cleanSender;
      inputMetadata.subject = cleanSubject;
      inputMetadata.rawLength = combinedInputText.length;
    } else if (modality === 'phone') {
      const preserveTargetPhone = options.preserveTargetPhone === true;
      const cleanPhone = redactPii ? sanitizePiiText(phoneNumber || '', { preserveTargetPhone }) : (phoneNumber || '');
      const cleanTranscript = redactPii ? sanitizePiiText(transcript || text || '') : (transcript || text || '');
      combinedInputText = `[CUỘC GỌI ĐIỆN THOẠI / BẢN GHI ÂM / VOICEMAIL]\nTên hiển thị (Caller ID): ${callerId || 'Không xác định / Không cung cấp'}\nSố điện thoại gọi đến: ${cleanPhone || 'Không xác định'}\nBản ghi nội dung đàm thoại:\n${cleanTranscript}`;
      inputMetadata.phoneNumber = cleanPhone;
      inputMetadata.callerId = callerId;
      inputMetadata.rawLength = combinedInputText.length;
    } else if (modality === 'url') {
      combinedInputText = `[ĐỊA CHỈ TRANG WEB / TÊN MIỀN URL]\nURL được gửi kiểm tra: ${url || text || ''}`;
      inputMetadata.url = url || text;
    } else if (modality === 'image') {
      combinedInputText = `[HÌNH ẢNH / TỆP TIN ĐỒ HỌA]\nChú thích / Văn bản nhận diện trong ảnh: ${text || 'Không có chú thích'}\nLoại hình: Tệp ảnh số (PNG/JPEG/WebP). Thực hiện phân tích nhận thức bố cục hình ảnh, cấu trúc đồ họa, văn bản cam kết tài chính phi thực tế và dấu hiệu hình ảnh nhân tạo. Lưu ý: Mô hình đánh giá các dấu hiệu âm thanh hoặc thị giác chưa nhất quán; không thay thế cho phần mềm chuyên dụng kiểm tra trắc sinh học.`;
      inputMetadata.mediaType = imageMimeType || 'image/jpeg';
    } else if (modality === 'video') {
      combinedInputText = `[VIDEO / BẢN GHI HÌNH & TIẾNG]\nBản ghi lời thoại / Nội dung âm thanh video:\n${videoTranscript || text || 'Không có bản ghi lời thoại'}\nLoại hình: Bản ghi video ngắn. Thực hiện phân tích nhịp điệu phát âm, ngữ cảnh ép buộc tài chính, kịch bản mạo danh lãnh đạo/người thân và các dấu hiệu giọng nói nhân tạo. Lưu ý: Mô hình đánh giá các dấu hiệu âm thanh hoặc thị giác chưa nhất quán; không thay thế cho phần mềm chuyên dụng kiểm tra trắc sinh học.`;
      inputMetadata.mediaType = 'video/mp4';
    }

    // Aggregate multi-source deterministic signals & pre-flight telemetry
    const threatTelemetry = await aggregateThreatTelemetry({
      modality,
      rawContent: combinedInputText,
      sender,
      subject,
      phoneNumber,
      callerId,
      url: url || text,
      clientBreachData: options.clientBreachData,
    });

    const ai = getGeminiClient();

    // Prepare prompt as Principal AI Safety Architect / Multi-Source Threat Intelligence Synthesizer
    const systemPrompt = `Bạn là TrustLens AI — Đóng vai trò Principal AI Safety Architect kiêm Trưởng ban Phân tích Tổng hợp Đe dọa Đa nguồn (Multi-Source Threat Intelligence Synthesizer).
Mục tiêu cốt lõi: Đưa ra nhận định an toàn số khách quan, trung thực và toàn diện bằng cách TỔNG HỢP VÀ ĐỐI CHIẾU CHÉO (CROSS-REFERENCE) giữa hai khối dữ liệu:
1. KHỐI <threat_telemetry>: Dữ liệu đo lường tiền trạm xác thực (Authoritative & Deterministic Telemetry):
   - <external_breach_data>: Lịch sử rò rỉ dữ liệu tài khoản/email đối soát qua k-Anonymity SHA-1 từ cơ sở dữ liệu Have I Been Pwned.
   - <url_structural_heuristics>: Phân tích cấu trúc hình thái URL (Punycode, Homoglyph ký tự giả mạo, cổng mạng bất thường, xếp tầng subdomain, danh mục rủi ro TLD).
   - <pii_indicators>: Dữ liệu định danh cá nhân nhạy cảm xuất hiện (CCCD 12 số, tài khoản ngân hàng, thẻ Napas/Visa, số điện thoại & nhà mạng viễn thông, mức độ thúc ép thời gian).
   - <national_trustmark_context>: Bối cảnh nhãn tín nhiệm quốc gia theo chuẩn Hệ thống Tín Nhiệm Mạng (NCSC) và Dự án Chống Lừa Đảo.

2. KHỐI <untrusted_user_input>: Nội dung người dùng gửi lên để sàng lọc.

QUY TẮC ĐÁNH GIÁ THEO HAI TRỤC TRỰC GIAO TUYỆT ĐỐI (ORTHOGONAL METRICS):
TRỤC 1: NGUY CƠ LỪA ĐẢO / GIAN LẬN (Scam Risk: 0 đến 100%)
- 0-25% (Rủi ro Thấp): Giao dịch minh bạch, tổ chức chính thống có chứng nhận tín nhiệm, không có thao túng tâm lý.
- 26-55% (Rủi ro Trung bình): Cần cảnh giác (thông tin chưa được đối soát, tên miền chưa có nhãn tín nhiệm, thông điệp tiếp thị bất thường).
- 56-80% (Rủi ro Cao): Khả năng lừa đảo rất cao (kịch bản thao túng tâm lý, tạo áp lực thời gian khẩn cấp, dụ dỗ cung cấp mật khẩu/mã OTP, mạo danh thương hiệu).
- 81-100% (Rủi ro Nghiêm trọng / Khẩn cấp): Dấu hiệu lừa đảo rõ ràng (Phishing giả mạo ngân hàng/công an, chiếm đoạt CCCD, link độc hại có homoglyph, yêu cầu nạp tiền).
LƯU Ý: Lừa đảo do con người tự biên soạn (kịch bản mạo danh viện kiểm sát, công an) có thể có 0% AI nhưng 100% Scam Risk.

QUY TẮC ĐẶC BIỆT ĐỐI VỚI ĐỊA CHỈ TRANG WEB / TÊN MIỀN (URL MODALITY) — 3-TIER URL THREAT INTELLIGENCE:
1. TIER A: TÊN MIỀN UY TÍN ĐÃ XÁC THỰC (0 - 5% Scam Risk, Xanh lá):
   - Các tên miền chính phủ, giáo dục, nền tảng lớn (*.gov.vn, *.chinhphu.vn, dichvucong.gov.vn, vneid.gov.vn, gdt.gov.vn, *.edu.vn, *.edu, google.com, github.com, youtube.com, facebook.com, vnexpress.net, tuoitre.vn...).
   - BẮT BUỘC: Scam Risk từ 1% đến 4% (Mức Thấp / Low Risk / Green).
   - Nhận định: "Tên miền thuộc tổ chức uy tín đã được xác thực an toàn."

2. TIER B: TÊN MIỀN DỰ ÁN SẠCH & WEBSITE BÌNH THƯỜNG (5 - 10% Scam Risk, Xanh lá):
   - Ví dụ: 'smartteenai.xyz', portfolio, blog, website giới thiệu sản phẩm/startup công nghệ, tên miền dự án cá nhân/doanh nghiệp sạch.
   - Điều kiện: KHÔNG chứa từ khóa mạo danh thương hiệu, KHÔNG giả mạo ngân hàng/công an, KHÔNG đòi mã OTP hay thông tin tài khoản, KHÔNG chứa liên kết tải file .apk/.exe độc hại.
   - NGUYÊN TẮC BẮT BUỘC: Các đuôi tên miền quốc tế thông dụng (.xyz, .top, .online, .site, .ai, .io, .app, .dev, .me) MỘT MÌNH NÓ TUYỆT ĐỐI KHÔNG PHẢI BẰNG CHỨNG LỪA ĐẢO. TUYỆT ĐỐI KHÔNG ĐƯỢC phạt 40-45% cho website sạch.
   - BẮT BUỘC: Scam Risk <= 10% (từ 5% đến 10%, Mức Thấp / Low Risk / Green).
   - Nhận định: "Mức độ rủi ro lừa đảo thấp. Tên miền sạch, không ghi nhận dấu hiệu giả mạo thương hiệu hay mã độc."

3. TIER C: TÊN MIỀN LỪA ĐẢO & ĐỘC HẠI THỰC SỰ (85 - 98% Scam Risk, Đỏ / Q3):
   - CHỈ gán mức Nguy cấp / Critical khi phát hiện chứng cứ tấn công rõ ràng:
     * Giả mạo thương hiệu ngân hàng / cơ quan công quyền trên TLD phi chính thức (ví dụ: vietcombank-login.xyz, vneid-portal.online, bidv-smartbanking.vip).
     * Đường dẫn chứa từ khóa bẫy đăng nhập/tải mã độc: /otp, /login-bank, /xac-minh, hoặc tải file .apk/.exe.
     * Sử dụng trực tiếp địa chỉ IP số (ví dụ: http://192.168.x.x).
     * Tấn công giả mạo ký tự (Homoglyph / Punycode xn--).
   - BẮT BUỘC: Scam Risk từ 85% đến 98% (Mức Nghiêm trọng / Critical / Red, Quadrant scam_human).

QUY TẮC BẮT BUỘC ĐỐI VỚI KỊCH BẢN CẤP CỨU BỆNH VIỆN, CƠ QUAN THUẾ, VÀ TỆP CÀI ĐẶT APK ĐỘC HẠI:
1. Tệp Cài Đặt Độc Hại (.APK Dropper) & Chiếm Quyền Trợ Năng Android:
   - Bất kỳ thông điệp nào chứa đường dẫn tải tệp có đuôi .apk (ví dụ: .apk, portal-app.apk, vneid-portal.apk...) bên ngoài kho ứng dụng chính thức Google Play: ĐÂY LÀ VÉC-TƠ MÃ ĐỘC TỐI NGUY HIỂM (Banking Trojan / Accessibility Service Hijack).
   - BẮT BUỘC ĐÁNH GIÁ:
     * Scam Risk: >= 96% (từ 96% đến 99%, Mức Nghiêm trọng / Critical).
     * AI Probability: <= 10% (từ 5% đến 10%, do kẻ gian trực tiếp thiết kế kịch bản lừa đảo).
     * Quadrant: scam_human (Góc phần tư 3: Lừa đảo do con người thao túng).
   - TUYỆT ĐỐI KHÔNG BAO GIỜ đánh giá dưới 90% cho bất kỳ email/tin nhắn nào dụ dỗ tải file .apk.

2. Giả mạo Cơ quan Thuế / Tổng cục Thuế / Truy thu Thuế:
   - Mạo danh Tổng cục Thuế, chi cục thuế, thông báo truy thu tiền thuế hoặc cưỡng chế phong tỏa tài khoản gửi từ tên miền không có đuôi .gov.vn: BẮT BUỘC Scam Risk >= 95%, AI <= 10%, Quadrant scam_human.

3. Bệnh viện Cấp cứu & Chuyển gấp viện phí (Hospital Emergency Scam):
   - Mọi thông điệp chứa nội dung báo tin người thân/con cái bị tai nạn, chấn thương sọ não, đang cấp cứu/hôn mê tại bệnh viện (như Chợ Rẫy, Bạch Mai, Việt Đức...) và yêu cầu chuyển tiền gấp tạm ứng viện phí trong thời gian ngắn (ví dụ: 15-30 phút) vào số tài khoản: ĐÂY LÀ ĐỈNH ĐIỂM CỦA THỦ ĐOÀN LỪA ĐẢO TỐNG TIỀN NGUY HIỂM (SPEAR-PHISHING EXTORTION).
   - BẮT BUỘC ĐÁNH GIÁ:
     * Scam Risk: >= 90% (từ 92% đến 96%, Mức Nghiêm trọng / Critical).
     * AI Probability: <= 10% (từ 5% đến 10%, do con người trực tiếp thao túng tâm lý).
     * Quadrant: scam_human (Góc phần tư 3: Lừa đảo do con người thao túng).
   - TUYỆT ĐỐI KHÔNG BAO GIỜ đánh giá rủi ro thấp cho kịch bản cấp cứu đòi chuyển tiền viện phí.

4. Mạo danh Công an / Viện kiểm sát / Khóa mã định danh VNeID:
   - Các kịch bản đe dọa tố tụng, phong tỏa tài khoản, yêu cầu chuyển tiền vào tài khoản tạm giữ hoặc cài file .apk: BẮT BUỘC Scam Risk >= 90%, AI <= 10%, Quadrant scam_human.

5. Tuyển CTV làm nhiệm vụ / Nạp tiền nhận hoa hồng:
   - BẮT BUỘC Scam Risk >= 85%, Quadrant scam_human.

6. Mạo danh Hải quan / Bưu cục Sân bay / Thông báo Kiện hàng Ngoại tệ đòi nộp tiền vào tài khoản cá nhân cán bộ:
   - Mọi thông báo kiện hàng chứa ngoại tệ/hàng cấm kèm yêu cầu nộp tiền phạt, phí thông quan gấp trong vòng vài giờ vào tài khoản cá nhân cán bộ, đe dọa chuyển cơ quan điều tra: BẮT BUỘC Scam Risk >= 92% (từ 92% đến 96%, Mức Nghiêm trọng / Critical), AI <= 15%, Quadrant scam_human. Cơ quan nhà nước và Hải quan KHÔNG BAO GIỜ yêu cầu chuyển tiền hay nộp phạt vào tài khoản cá nhân của cán bộ!

TRỤC 2: XÁC SUẤT NỘI DUNG DO AI TẠO RA HOẶC BỊ CHỈNH SỬA (AI Probability: 0 đến 100%)
- 0-20%: Khả năng cao do con người tạo ra (văn phong đời thường, biến thể tự nhiên).
- 21-50%: Có dấu hiệu chỉnh sửa bằng AI / Hỗn hợp (dịch máy, công cụ hỗ trợ văn bản).
- 51-80%: Khả năng cao do AI tạo ra (cấu trúc câu đặc trưng của LLM, văn phong tổng hợp đều đặn).
- 81-100%: Nội dung nhân tạo tổng hợp / Deepfake (văn bản thuần AI, giọng nói nhân tạo voice clone, hình ảnh khuếch tán diffusion/GAN).
LƯU Ý: Nội dung AI lành tính (như email chào mừng tự động, bản tin) có thể có 100% AI Probability nhưng 0% Scam Risk.

QUY TẮC TỔNG HỢP TRÍ TUỆ ĐA NGUỒN (MULTI-SOURCE THREAT SYNTHESIS):
1. Đối chiếu chéo (Cross-reference):
   - Khi <url_structural_heuristics> ghi nhận homoglyph="DETECTED" hoặc phát hiện thương hiệu giả mạo mà <national_trustmark_context status="UNVERIFIED_THIRD_PARTY_DOMAIN"> hoặc "SUSPECTED_PHISHING_DOMAIN", phải kết luận ngay đây là chiến dịch tấn công giả mạo (Phishing) với độ nguy hiểm rất cao.
   - Khi <external_breach_data status="PWNED_..."/>, cảnh báo rõ nguy cơ bị tấn công dò quét mật khẩu (Credential Stuffing) và chiếm đoạt tài khoản.
   - Khi <pii_indicators detected_cccd="PRESENT" detected_bank_account="PRESENT"/> kết hợp với urgency_level="CRITICAL", phân tích sâu thủ đoạn chiếm đoạt hồ sơ tín dụng hoặc đe dọa tố tụng hình sự.
2. Phản ánh trung thực vào các trường đầu ra:
   - Trong methodologyBreakdown.deterministicChecks: Liệt kê rõ ràng các bước tiền trạm từ telemetry (ví dụ: 'Đối soát k-Anonymity HIBP', 'Phân tích Punycode/Homoglyph', 'Nhận diện PII định danh Việt Nam', 'Tra cứu ngữ cảnh Tín Nhiệm Mạng').
   - Trong scamRisk.indicators: Gắn nhãn nguồn gốc chính xác (provenance: 'DETERMINISTIC' cho các tín hiệu cấu trúc/cú pháp, 'EXTERNAL_SOURCE' cho dữ liệu Have I Been Pwned, 'AI_HEURISTIC' cho nhận định ngữ nghĩa mô hình).
   - Trong verificationSources: Cung cấp đầy đủ trạng thái đối soát (Have I Been Pwned, Hệ thống Tín Nhiệm Mạng, Kiểm tra Cấu trúc URI).
3. Toàn bộ câu trả lời, nhận định, khuyến nghị và giải thích phải bằng TIẾNG VIỆT tự nhiên, chuẩn mực, mang phong cách của một chuyên gia an toàn thông tin hàng đầu.
4. Xuất định dạng JSON hợp lệ theo đúng schema quy định.`;


    let analysisOutput: any = null;
    let engineUsed: 'gemini_multimodal' | 'LOCAL_FALLBACK' = 'LOCAL_FALLBACK';

    if (ai) {
      const enrichedUserPrompt = `${threatTelemetry.xmlEnvelope}
<untrusted_user_input>
${combinedInputText}
</untrusted_user_input>`;

      const parts: any[] = [{ text: enrichedUserPrompt }];

      // Multimodal image support
      if (modality === 'image' && imageDataBase64) {
        const cleanBase64 = imageDataBase64.includes(',')
          ? imageDataBase64.split(',')[1]
          : imageDataBase64;
        parts.unshift({
          inlineData: {
            mimeType: imageMimeType || 'image/jpeg',
            data: cleanBase64,
          },
        });
      }

      // Multimodal video frames support
      if (modality === 'video' && Array.isArray(videoFramesBase64) && videoFramesBase64.length > 0) {
        for (const frame of videoFramesBase64.slice(0, 3)) {
          const cleanBase64 = frame.includes(',') ? frame.split(',')[1] : frame;
          parts.unshift({
            inlineData: {
              mimeType: 'image/jpeg',
              data: cleanBase64,
            },
          });
        }
      }

      const responseSchema = {
        type: Type.OBJECT,
        properties: {
          inputSummary: { type: Type.STRING },
          scamRisk: {
            type: Type.OBJECT,
            properties: {
              score: { type: Type.NUMBER, description: '0 to 100 risk score (e.g. 95)' },
              level: { type: Type.STRING, description: 'low, medium, high, or critical' },
              confidence: { type: Type.NUMBER, description: '0 to 100 confidence' },
              summary: { type: Type.STRING },
              tactics: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
              indicators: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING },
                    title: { type: Type.STRING },
                    severity: { type: Type.STRING, description: 'low, medium, high, or critical' },
                    category: { type: Type.STRING },
                    description: { type: Type.STRING },
                    evidenceSnippet: { type: Type.STRING },
                    provenance: { type: Type.STRING, description: 'DETERMINISTIC, AI_HEURISTIC, EXTERNAL_SOURCE, or UNAVAILABLE' },
                  },
                  required: ['id', 'title', 'severity', 'category', 'description', 'provenance'],
                },
              },
              impactAssessment: { type: Type.STRING },
            },
            required: ['score', 'level', 'confidence', 'summary', 'tactics', 'indicators', 'impactAssessment'],
          },
          aiProbability: {
            type: Type.OBJECT,
            properties: {
              score: { type: Type.NUMBER, description: '0 to 100 probability (e.g. 8)' },
              level: { type: Type.STRING, description: 'Likely Authentic / Human, Possible AI Editing / Mixed, Likely AI-Generated, or Highly Synthetic / Deepfake' },
              confidence: { type: Type.NUMBER, description: '0 to 100 confidence' },
              summary: { type: Type.STRING },
              primaryType: { type: Type.STRING },
              indicators: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING },
                    title: { type: Type.STRING },
                    anomalyType: { type: Type.STRING },
                    confidence: { type: Type.NUMBER },
                    description: { type: Type.STRING },
                    provenance: { type: Type.STRING, description: 'DETERMINISTIC, AI_HEURISTIC, EXTERNAL_SOURCE, or UNAVAILABLE' },
                  },
                  required: ['id', 'title', 'anomalyType', 'confidence', 'description', 'provenance'],
                },
              },
              technicalCues: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
            },
            required: ['score', 'level', 'confidence', 'summary', 'primaryType', 'indicators', 'technicalCues'],
          },
          quadrantClassification: {
            type: Type.OBJECT,
            properties: {
              quadrant: { type: Type.STRING, description: 'benign_human, benign_ai, scam_human, or scam_ai' },
              title: { type: Type.STRING },
              explanation: { type: Type.STRING },
            },
            required: ['quadrant', 'title', 'explanation'],
          },
          methodologyBreakdown: {
            type: Type.OBJECT,
            properties: {
              deterministicChecks: { type: Type.ARRAY, items: { type: Type.STRING } },
              extractedEvidence: { type: Type.ARRAY, items: { type: Type.STRING } },
              aiReasoning: { type: Type.ARRAY, items: { type: Type.STRING } },
              unconnectedTelemetry: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ['deterministicChecks', 'extractedEvidence', 'aiReasoning', 'unconnectedTelemetry'],
          },
          verificationSources: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                name: { type: Type.STRING },
                category: { type: Type.STRING },
                status: { type: Type.STRING, description: 'verified_format, heuristic_pass, suspicious, malicious, offline_heuristic, preliminary_inspection, or unavailable_no_live_feed' },
                statusLabel: { type: Type.STRING },
                details: { type: Type.STRING },
                isSimulatedOrPreliminary: { type: Type.BOOLEAN },
                limitationNote: { type: Type.STRING },
                provenance: { type: Type.STRING, description: 'DETERMINISTIC, AI_HEURISTIC, EXTERNAL_SOURCE, or UNAVAILABLE' },
              },
              required: ['name', 'category', 'status', 'statusLabel', 'details', 'isSimulatedOrPreliminary', 'provenance'],
            },
          },
          limitations: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
          },
          recommendedActions: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                action: { type: Type.STRING },
                priority: { type: Type.STRING, description: 'immediate, recommended, or optional' },
                rationale: { type: Type.STRING },
              },
              required: ['action', 'priority', 'rationale'],
            },
          },
          educationalTakeaway: { type: Type.STRING },
        },
        required: [
          'inputSummary',
          'scamRisk',
          'aiProbability',
          'quadrantClassification',
          'verificationSources',
          'limitations',
          'recommendedActions',
          'educationalTakeaway',
        ],
      };

      // Multi-tier model candidate pool with automatic failover to prevent 503 high demand outages
      const CANDIDATE_MODELS = ['gemini-3.1-flash-lite', 'gemini-3.6-flash', 'gemini-3.8-flash'];
      let geminiSuccess = false;

      for (const model of CANDIDATE_MODELS) {
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            const response = await ai.models.generateContent({
              model,
              contents: { parts },
              config: {
                systemInstruction: systemPrompt,
                responseMimeType: 'application/json',
                responseSchema,
              },
            });

            if (response.text) {
              const cleanJson = response.text.trim().replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
              const parsed = JSON.parse(cleanJson);
              if (parsed.scamRisk) {
                parsed.scamRisk.score = normalizeScoreTo100(parsed.scamRisk.score, 0);
              }
              if (parsed.aiProbability) {
                parsed.aiProbability.score = normalizeScoreTo100(parsed.aiProbability.score, 0);
              }
              if (parsed.quadrantClassification) {
                parsed.quadrantClassification = normalizeQuadrant(
                  parsed.quadrantClassification.quadrant || parsed.quadrantClassification,
                  parsed.scamRisk?.score ?? 0,
                  parsed.aiProbability?.score ?? 0
                );
              }
              analysisOutput = parsed;
              engineUsed = 'gemini_multimodal';
              geminiSuccess = true;
              break;
            }
          } catch (err: any) {
            const msg = err?.message || String(err);
            const isTransient = msg.includes('503') || msg.includes('429') || msg.includes('UNAVAILABLE') || msg.includes('high demand') || msg.includes('RESOURCE_EXHAUSTED');
            if (isTransient && attempt === 0) {
              // Wait briefly before 2nd attempt on transient error
              await new Promise((r) => setTimeout(r, 600 + Math.random() * 200));
              continue;
            }
            // Move to next candidate model
            break;
          }
        }
        if (geminiSuccess) break;
      }

      if (!geminiSuccess) {
        console.warn('Gemini API tạm thời không phản hồi (503/429), kích hoạt cơ chế bảo vệ phân tích cục bộ xác định (LOCAL_FALLBACK).');
      }
    }

    // Local deterministic heuristic analysis (guaranteed protection against emergency/extortion spear-phishing)
    const localDeterministicResult = analyzeLocally(
      modality,
      combinedInputText,
      {
        sender,
        subject,
        phoneNumber,
        callerId,
        url: url || text,
        transcript: transcript || text || videoTranscript,
      },
      threatTelemetry
    );

    // Fallback heuristic model if API key is not present or Gemini failed
    if (!analysisOutput) {
      analysisOutput = localDeterministicResult;
      engineUsed = 'LOCAL_FALLBACK';
      analysisOutput.fallbackReason = ai ? 'Lỗi kết nối Gemini API, sử dụng engine phân tích ngoại tuyến.' : 'Không tìm thấy API Key, chạy ở chế độ LOCAL_FALLBACK.';
    } else if (localDeterministicResult.scamRisk.score >= 85 && (analysisOutput.scamRisk?.score ?? 0) < localDeterministicResult.scamRisk.score) {
      // Safety guardrail against LLM false negatives on critical extortion/hospital emergency/malicious APK vectors
      console.warn('Cảnh báo an toàn: Phát hiện dấu hiệu đe dọa nghiêm trọng qua quy tắc xác định. Kích hoạt lớp bảo vệ an toàn tối cao.');
      analysisOutput.scamRisk.score = Math.max(analysisOutput.scamRisk.score || 0, localDeterministicResult.scamRisk.score);
      analysisOutput.scamRisk.level = localDeterministicResult.scamRisk.level;
      analysisOutput.scamRisk.summary = localDeterministicResult.scamRisk.summary;
      analysisOutput.scamRisk.tactics = Array.from(new Set([...(analysisOutput.scamRisk.tactics || []), ...localDeterministicResult.scamRisk.tactics]));
      analysisOutput.scamRisk.indicators = [...localDeterministicResult.scamRisk.indicators, ...(analysisOutput.scamRisk.indicators || [])];
      if (!analysisOutput.aiProbability) analysisOutput.aiProbability = localDeterministicResult.aiProbability;
      else {
        analysisOutput.aiProbability.score = Math.min(analysisOutput.aiProbability.score, localDeterministicResult.aiProbability.score);
        analysisOutput.aiProbability.level = localDeterministicResult.aiProbability.level;
      }
      analysisOutput.quadrantClassification = localDeterministicResult.quadrantClassification;
      analysisOutput.recommendedActions = localDeterministicResult.recommendedActions;
    }

    // Specific URL Modality 3-Tier Threat Intelligence Guardrail
    if (modality === 'url') {
      const targetUrl = (url || text || '').trim();
      const urlIntel = evaluateUrlThreatIntelligence(targetUrl);
      if (urlIntel.tier === 'TIER_A_WHITELIST') {
        // Enforce 1 - 5% (Safe / Low Risk, Green)
        const currentScore = analysisOutput.scamRisk?.score ?? 3;
        analysisOutput.scamRisk.score = currentScore <= 5 ? (currentScore === 0 ? 3 : currentScore) : 3;
        analysisOutput.scamRisk.level = 'low';
        analysisOutput.scamRisk.summary = urlIntel.verdict;
        // Filter out false positive flags
        analysisOutput.scamRisk.indicators = (analysisOutput.scamRisk.indicators || []).filter(
          (ind: any) => ind.severity !== 'high' && ind.severity !== 'critical' && ind.severity !== 'medium'
        );
      } else if (urlIntel.tier === 'TIER_B_BENIGN') {
        // Enforce 5 - 10% (Low Risk / Green, strictly <= 10%) for Clean Benign domains (e.g. smartteenai.xyz)
        const currentScore = analysisOutput.scamRisk?.score ?? 7;
        analysisOutput.scamRisk.score = currentScore <= 10 ? Math.max(5, currentScore) : 7;
        analysisOutput.scamRisk.level = 'low';
        analysisOutput.scamRisk.summary = urlIntel.verdict;
        // Strip out generic TLD or false positive medium/high flags
        analysisOutput.scamRisk.indicators = (analysisOutput.scamRisk.indicators || []).filter(
          (ind: any) => ind.severity !== 'high' && ind.severity !== 'critical' && ind.severity !== 'medium'
        );
      } else if (urlIntel.tier === 'TIER_C_MALICIOUS') {
        analysisOutput.scamRisk.score = Math.max(analysisOutput.scamRisk?.score ?? 0, urlIntel.scamScore);
        analysisOutput.scamRisk.level = 'critical';
        analysisOutput.scamRisk.summary = urlIntel.verdict;
      }
    }

    // Default methodology breakdown if not provided by Gemini
    const defaultMethodology: Record<string, string[]> = {
      deterministicChecks: [
        'Bộ quy tắc nhận diện cấu trúc cú pháp URI / Email (RFC 5322 & RFC 3986)',
        'Mẫu biểu thức chính quy (Regex) quét số CCCD, thẻ ngân hàng, SĐT và email cá nhân',
        'Bộ lọc từ khóa tâm lý ép buộc, chuyển khoản tài chính không thể hoàn tác và mạo danh thương hiệu',
        'Đối soát tín hiệu rò rỉ dữ liệu k-Anonymity SHA-1 từ Have I Been Pwned',
        'Kiểm tra định danh tên miền và bối cảnh chuẩn Tín Nhiệm Mạng Quốc Gia'
      ],
      extractedEvidence: analysisOutput.scamRisk?.indicators?.map((i: any) => i.evidenceSnippet).filter(Boolean) || [],
      aiReasoning: [
        'Mô hình đánh giá ngữ nghĩa và phát hiện kịch bản thao túng tâm lý (Social Engineering)',
        'Phân tích tính trực giao giữa nguồn gốc tác giả (Human/AI) và ý đồ hành vi (Lừa đảo/Lành tính)',
        'Tổng hợp tín hiệu từ bộ telemetry tiền trạm với ngữ cảnh nội dung người dùng cung cấp'
      ],
      unconnectedTelemetry: [
        'Dữ liệu xác thực chữ ký cuộc gọi STIR/SHAKEN từ nhà mạng viễn thông: Chưa kết nối',
        'Truy vấn bản ghi DNS DKIM/DMARC thời gian thực: Cần cung cấp raw email header đầy đủ',
        'Mô hình GPU phân tích quang học rPPG nhịp tim và PRNU cảm biến máy ảnh: Chưa kết nối'
      ]
    };

    // Calculate final sanitized response object
    const result = {
      id: `TL-${Date.now().toString().slice(-6)}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      modality,
      engineUsed,
      analysisMode: engineUsed,
      fallbackReason: analysisOutput.fallbackReason || null,
      inputSummary: analysisOutput.inputSummary || `Kiểm tra sàng lọc dữ liệu hình thức ${modality.toUpperCase()}.`,
      inputMetadata,
      threatTelemetry,
      scamRisk: {
        score: normalizeScoreTo100(analysisOutput.scamRisk?.score, 0),
        level: normalizeSeverity(normalizeScoreTo100(analysisOutput.scamRisk?.score, 0)),
        confidence: Math.min(100, Math.max(10, Math.round(analysisOutput.scamRisk?.confidence ?? 80))),
        summary: analysisOutput.scamRisk?.summary || 'Đã hoàn tất đánh giá nguy cơ lừa đảo.',
        tactics: analysisOutput.scamRisk?.tactics || [],
        indicators: (analysisOutput.scamRisk?.indicators || []).map((ind: any, i: number) => ({
          id: ind.id || `ind-${i}`,
          title: ind.title || 'Dấu hiệu Rủi ro',
          severity: ind.severity || 'medium',
          category: ind.category || 'urgency',
          description: ind.description || 'Dấu hiệu rủi ro quan sát được trong dữ liệu gửi lên.',
          evidenceSnippet: ind.evidenceSnippet,
          provenance: ind.provenance || 'DETERMINISTIC',
        })),
        impactAssessment: analysisOutput.scamRisk?.impactAssessment || 'Khuyến nghị tuân thủ quy tắc bảo mật kỹ thuật số tiêu chuẩn.',
      },
      aiProbability: {
        score: normalizeScoreTo100(analysisOutput.aiProbability?.score, 0),
        level: normalizeAiLevel(normalizeScoreTo100(analysisOutput.aiProbability?.score, 0)),
        confidence: Math.min(100, Math.max(10, Math.round(analysisOutput.aiProbability?.confidence ?? 75))),
        summary: analysisOutput.aiProbability?.summary || 'Đã hoàn tất kiểm tra ngôn ngữ học & tính chất nhân tạo.',
        primaryType: analysisOutput.aiProbability?.primaryType || 'Do con người soạn thảo / Không có dấu hiệu AI',
        indicators: (analysisOutput.aiProbability?.indicators || []).map((ind: any, i: number) => ({
          id: ind.id || `ai-ind-${i}`,
          title: ind.title || 'Đặc điểm Cấu trúc',
          anomalyType: ind.anomalyType || 'linguistic_pattern',
          confidence: ind.confidence || 70,
          description: ind.description || 'Dấu hiệu nhân tạo có thể quan sát được.',
          provenance: ind.provenance || 'AI_HEURISTIC',
        })),
        technicalCues: analysisOutput.aiProbability?.technicalCues || [],
      },
      quadrantClassification: normalizeQuadrant(
        analysisOutput.quadrantClassification,
        normalizeScoreTo100(analysisOutput.scamRisk?.score, 0),
        normalizeScoreTo100(analysisOutput.aiProbability?.score, 0)
      ),
      methodologyBreakdown: analysisOutput.methodologyBreakdown || defaultMethodology,
      fiveDimensionalBreakdown: analysisOutput.fiveDimensionalBreakdown || localDeterministicResult.fiveDimensionalBreakdown,
      stylometricMetrics: analysisOutput.stylometricMetrics || localDeterministicResult.stylometricMetrics,
      verificationSources: (analysisOutput.verificationSources || []).map((src: any) => ({
        name: src.name || 'Kiểm tra Cấu trúc Quy tắc',
        category: src.category || 'Quy tắc Xác định (Deterministic Heuristics)',
        status: src.status || 'offline_heuristic',
        statusLabel: src.statusLabel || (src.status === 'malicious' ? 'Khớp Mẫu Độc Hại' : src.status === 'suspicious' ? 'Dấu hiệu Đáng Ngờ' : 'Kiểm Tra Ngoại Tuyến'),
        details: src.details || 'Phân tích dựa trên tập quy tắc cú pháp và mẫu hành vi xác định.',
        isSimulatedOrPreliminary: src.isSimulatedOrPreliminary !== false,
        limitationNote: src.limitationNote,
        provenance: src.provenance || 'DETERMINISTIC',
      })),
      limitations: analysisOutput.limitations || [
        'Đánh giá mang tính xác suất; nên thực hiện xác minh độc lập qua số điện thoại hoặc cổng thông tin chính thức của đơn vị liên quan.',
        'Kẻ lừa đảo con người có thể tự soạn kịch bản thao túng tâm lý mà không cần dùng bất kỳ công cụ AI nào.',
      ],
      recommendedActions: analysisOutput.recommendedActions || [
        {
          action: 'Xác minh qua kênh liên lạc độc lập',
          priority: 'recommended',
          rationale: 'Liên hệ trực tiếp với cơ quan hoặc doanh nghiệp liên quan qua số điện thoại/website tra cứu độc lập, không dùng số/link trong tin nhắn.',
        }
      ],
      educationalTakeaway: analysisOutput.educationalTakeaway || 'Luôn đánh giá ý đồ và mục đích của thông điệp một cách độc lập với việc thông điệp đó do người hay AI tạo ra.',
      rawInputSnippet: combinedInputText.slice(0, 260),
    };

    res.json(result);
  } catch (error: any) {
    console.error('Lỗi máy chủ khi xử lý phân tích:', error);
    res.status(500).json({
      error: 'Đã xảy ra lỗi nội bộ trong quá trình xử lý phân tích.',
      details: error.message || 'Lỗi xử lý không xác định',
    });
  }
});

// Helper normalization functions
function normalizeScoreTo100(raw: any, fallback = 0): number {
  if (raw === undefined || raw === null || isNaN(Number(raw))) return fallback;
  const num = Number(raw);
  // If the model output a decimal probability (e.g. 0.95 or 0.12 instead of 95 or 12)
  if (num > 0 && num <= 1) {
    return Math.round(num * 100);
  }
  return Math.min(100, Math.max(0, Math.round(num)));
}

function normalizeQuadrant(rawQuadrant: any, scamScore: number, aiScore: number) {
  if (typeof rawQuadrant === 'string') {
    const qLower = rawQuadrant.toLowerCase().trim();
    if (qLower === 'q1' || qLower === 'benign_human') {
      return {
        quadrant: 'benign_human',
        title: 'Góc phần tư 1: Giao tiếp Con người Chân thực (Lành tính)',
        explanation: 'Nội dung mang đặc trưng giao tiếp tự nhiên của con người, không có yếu tố lừa đảo, đe dọa hay thao túng tâm lý.',
      };
    }
    if (qLower === 'q2' || qLower === 'benign_ai') {
      return {
        quadrant: 'benign_ai',
        title: 'Góc phần tư 2: Nội dung AI Lành tính & Minh bạch',
        explanation: 'Nội dung thể hiện rõ dấu vết cấu trúc do mô hình AI tạo ra, nhưng an toàn tuyệt đối, không chứa liên kết độc hại hay yêu cầu chiếm đoạt tài sản.',
      };
    }
    if (qLower === 'q3' || qLower === 'scam_human') {
      return {
        quadrant: 'scam_human',
        title: 'Góc phần tư 3: Lừa đảo do Con người thao túng (Phi kỹ thuật)',
        explanation: 'Kịch bản lừa đảo truyền thống do con người tự soạn thảo (mạo danh cơ quan công an, đe dọa khóa tài khoản, hóa đơn giả) có nguy cơ lừa đảo cao dù AI = 0%.',
      };
    }
    if (qLower === 'q4' || qLower === 'scam_ai') {
      return {
        quadrant: 'scam_ai',
        title: 'Góc phần tư 4: Lừa đảo có sự hỗ trợ của AI / Deepfake',
        explanation: 'Chiến dịch lừa đảo tinh vi sử dụng giọng nói nhân tạo (voice clone), hình ảnh tổng hợp hoặc kịch bản AI tự động hóa để đánh lừa nạn nhân.',
      };
    }
  } else if (rawQuadrant && typeof rawQuadrant === 'object' && rawQuadrant.quadrant) {
    return normalizeQuadrant(rawQuadrant.quadrant, scamScore, aiScore);
  }
  return computeQuadrant(scamScore, aiScore);
}

function normalizeSeverity(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 81) return 'critical';
  if (score >= 56) return 'high';
  if (score >= 26) return 'medium';
  return 'low';
}

function normalizeAiLevel(score: number): string {
  if (score >= 81) return 'Highly Synthetic / Deepfake';
  if (score >= 51) return 'Likely AI-Generated';
  if (score >= 21) return 'Possible AI Editing / Mixed';
  return 'Likely Authentic / Human';
}

function computeQuadrant(scamScore: number, aiScore: number) {
  const isHighScam = scamScore >= 50;
  const isHighAi = aiScore >= 50;

  if (!isHighScam && !isHighAi) {
    return {
      quadrant: 'benign_human',
      title: 'Góc phần tư 1: Giao tiếp Con người Chân thực (Lành tính)',
      explanation: 'Nội dung mang đặc trưng giao tiếp tự nhiên của con người, không có yếu tố lừa đảo, đe dọa hay thao túng tâm lý.',
    };
  } else if (!isHighScam && isHighAi) {
    return {
      quadrant: 'benign_ai',
      title: 'Góc phần tư 2: Nội dung AI Lành tính & Minh bạch',
      explanation: 'Nội dung thể hiện rõ dấu vết cấu trúc do mô hình AI tạo ra, nhưng an toàn tuyệt đối, không chứa liên kết độc hại hay yêu cầu chiếm đoạt tài sản.',
    };
  } else if (isHighScam && !isHighAi) {
    return {
      quadrant: 'scam_human',
      title: 'Góc phần tư 3: Lừa đảo do Con người thao túng (Phi kỹ thuật)',
      explanation: 'Kịch bản lừa đảo truyền thống do con người tự soạn thảo (mạo danh cơ quan công an, đe dọa khóa tài khoản, hóa đơn giả) có nguy cơ lừa đảo cao dù AI = 0%.',
    };
  } else {
    return {
      quadrant: 'scam_ai',
      title: 'Góc phần tư 4: Lừa đảo có sự hỗ trợ của AI / Deepfake',
      explanation: 'Chiến dịch lừa đảo tinh vi sử dụng giọng nói nhân tạo (voice clone), hình ảnh tổng hợp hoặc kịch bản AI tự động hóa để đánh lừa nạn nhân.',
    };
  }
}

// Rich modality-specific offline deterministic heuristic engine
function generateModalitySpecificHeuristicAnalysis(
  modality: string, 
  rawCombined: string, 
  meta: { sender?: string; subject?: string; phoneNumber?: string; callerId?: string; url?: string; transcript?: string },
  telemetry?: AggregatedThreatTelemetry
) {
  return analyzeLocally(modality, rawCombined, meta, telemetry);
}

// Start Server with Vite
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TrustLens AI server running at http://0.0.0.0:${PORT}`);
  });
}

startServer();

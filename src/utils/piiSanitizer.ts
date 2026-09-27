/**
 * Bộ lọc làm sạch và che giấu Dữ liệu Cá nhân (PII Sanitization)
 * Thiết kế cho nền tảng TrustLens AI, tối ưu cho định dạng dữ liệu tại Việt Nam.
 * Thực thi trực tiếp tại trình duyệt trước khi gửi yêu cầu mạng.
 */

export interface PiiSanitizeOptions {
  preserveTargetPhone?: boolean;
}

/**
 * Che dấu các thông tin định danh cá nhân nhạy cảm trong văn bản.
 * - Căn cước công dân (CCCD) 12 số: \b0\d{11}\b -> [ĐÃ CHE CCCD]
 * - Số tài khoản ngân hàng (STK 8-16 chữ số kèm từ khóa) -> [ĐÃ CHE STK]
 * - Số thẻ thanh toán quốc tế / nội địa (16 chữ số Visa/Master/Napas) -> [ĐÃ CHE SỐ THẺ]
 * - Mã xác thực OTP (6 chữ số) -> [ĐÃ CHE OTP]
 * - Địa chỉ Email -> [ĐÃ CHE EMAIL]
 * - Số điện thoại Việt Nam -> [ĐÃ CHE SĐT] (trừ khi preserveTargetPhone = true)
 */
export function sanitizeClientPii(text: string, options: PiiSanitizeOptions = {}): string {
  if (!text) return '';

  let sanitized = text;

  // 1. Mã OTP 6 chữ số (đi kèm từ khóa mã xác thực / OTP)
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

  // 6. Số điện thoại (nếu không yêu cầu giữ lại để tra cứu viễn thông)
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

import { AnalysisResult } from '../types';
import { analyzeLocally, LocalHeuristicResult } from './localHeuristicEngine';

export function formatLocalResultToAnalysisResult(
  localResult: LocalHeuristicResult,
  payload: any
): AnalysisResult {
  const modality = payload?.modality || 'text';
  const combinedText = (
    payload?.text ||
    payload?.url ||
    payload?.transcript ||
    payload?.videoTranscript ||
    ''
  );

  const defaultMethodology = {
    deterministicChecks: [
      'Bộ quy tắc nhận diện cấu trúc cú pháp URI / Email (RFC 5322 & RFC 3986)',
      'Mẫu biểu thức chính quy (Regex) quét số CCCD, thẻ ngân hàng, SĐT và email cá nhân',
      'Bộ lọc từ khóa tâm lý ép buộc, chuyển khoản tài chính không thể hoàn tác và mạo danh thương hiệu',
      'Đối soát tín hiệu rò rỉ dữ liệu k-Anonymity SHA-1 từ Have I Been Pwned',
      'Kiểm tra định danh tên miền và bối cảnh chuẩn Tín Nhiệm Mạng Quốc Gia',
    ],
    extractedEvidence:
      localResult.scamRisk?.indicators?.map((i: any) => i.evidenceSnippet).filter(Boolean) || [],
    aiReasoning: [
      'Mô hình đánh giá ngữ nghĩa và phát hiện kịch bản thao túng tâm lý (Social Engineering)',
      'Phân tích tính trực giao giữa nguồn gốc tác giả (Human/AI) và ý đồ hành vi (Lừa đảo/Lành tính)',
      'Tổng hợp tín hiệu từ bộ telemetry tiền trạm với ngữ cảnh nội dung người dùng cung cấp',
    ],
    unconnectedTelemetry: [
      'Dữ liệu xác thực chữ ký cuộc gọi STIR/SHAKEN từ nhà mạng viễn thông: Ngoại tuyến',
      'Truy vấn bản ghi DNS DKIM/DMARC thời gian thực: Hoạt động chế độ ngoại tuyến an toàn',
      'Mô hình GPU phân tích quang học rPPG nhịp tim và PRNU cảm biến máy ảnh: Chưa kết nối',
    ],
  };

  return {
    id: `TL-LOCAL-${Date.now().toString().slice(-6)}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    modality,
    engineUsed: 'LOCAL_FALLBACK',
    analysisMode: 'LOCAL_FALLBACK',
    fallbackReason:
      localResult.fallbackReason ||
      'Chế độ ngoại tuyến / Preview an toàn (Động cơ Phân tích Quy tắc Xác định Cục bộ - Local Heuristic Engine)',
    inputSummary:
      localResult.inputSummary ||
      `Kiểm tra sàng lọc dữ liệu an toàn cho phương thức ${String(modality).toUpperCase()}.`,
    inputMetadata: {
      sender: payload?.sender,
      subject: payload?.subject,
      phoneNumber: payload?.phoneNumber,
      callerId: payload?.callerId,
      url: payload?.url,
      rawLength: combinedText.length,
    },
    scamRisk: {
      score: localResult.scamRisk?.score ?? 0,
      level: localResult.scamRisk?.level ?? 'low',
      confidence: localResult.scamRisk?.confidence ?? 85,
      summary: localResult.scamRisk?.summary || 'Đã hoàn tất kiểm tra rủi ro lừa đảo cục bộ.',
      tactics: localResult.scamRisk?.tactics || [],
      indicators: (localResult.scamRisk?.indicators || []).map((ind, i) => ({
        id: ind.id || `local-ind-${i}`,
        title: ind.title,
        severity: ind.severity,
        category: ind.category,
        description: ind.description,
        evidenceSnippet: ind.evidenceSnippet,
        provenance: ind.provenance || 'DETERMINISTIC',
      })),
      impactAssessment:
        localResult.scamRisk?.impactAssessment ||
        'Tuân thủ khuyến cáo bảo mật kỹ thuật số tiêu chuẩn.',
    },
    aiProbability: {
      score: localResult.aiProbability?.score ?? 0,
      level: localResult.aiProbability?.level ?? 'Likely Authentic / Human',
      confidence: localResult.aiProbability?.confidence ?? 80,
      summary:
        localResult.aiProbability?.summary || 'Hoàn tất đối soát ngôn ngữ và dấu vết cấu trúc.',
      primaryType:
        localResult.aiProbability?.primaryType || 'Do con người soạn thảo / Không có dấu hiệu AI',
      indicators: (localResult.aiProbability?.indicators || []).map((ind, i) => ({
        id: ind.id || `local-ai-ind-${i}`,
        title: ind.title,
        anomalyType: ind.anomalyType,
        confidence: ind.confidence,
        description: ind.description,
        provenance: ind.provenance || 'AI_HEURISTIC',
      })),
      technicalCues: localResult.aiProbability?.technicalCues || [],
    },
    quadrantClassification: localResult.quadrantClassification || {
      quadrant: 'benign_human',
      title: 'Góc phần tư 1: Giao tiếp Con người Chân thực (Lành tính)',
      explanation: 'Nội dung tự nhiên, không ghi nhận dấu hiệu lừa đảo hay thao túng tâm lý.',
    },
    methodologyBreakdown: defaultMethodology,
    fiveDimensionalBreakdown: localResult.fiveDimensionalBreakdown,
    stylometricMetrics: localResult.stylometricMetrics,
    verificationSources: localResult.verificationSources || [],
    limitations: localResult.limitations || [
      'Đánh giá dựa trên tập quy tắc ngoại tuyến độc lập, an toàn khi không có kết nối máy chủ.',
      'Luôn đối soát độc lập thông tin qua các kênh chính thống đã được công bố của cơ quan/doanh nghiệp.',
    ],
    recommendedActions: localResult.recommendedActions || [
      {
        action: 'Xác minh qua kênh liên lạc độc lập',
        priority: 'recommended',
        rationale:
          'Liên hệ trực tiếp qua số hotline hoặc website chính thức được công bố độc lập, không dùng số/link trong nội dung kiểm tra.',
      },
    ],
    educationalTakeaway:
      localResult.educationalTakeaway ||
      'Luôn xem xét mục đích thực tế của thông điệp một cách độc lập với việc thông điệp đó do người hay AI tạo ra.',
    rawInputSnippet: combinedText.slice(0, 260),
  };
}

/**
 * Bulletproof analysis caller:
 * 1. Attempts /api/analyze network call.
 * 2. If network/server fails (offline, preview mode, cold start, 503, etc.),
 *    silently falls back to analyzeLocally without throwing console errors or unhandled rejections.
 */
export async function performSafeAnalysis(payload: any): Promise<AnalysisResult> {
  // Step 1: Attempt network call to /api/analyze
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      const data = await response.json();
      if (data && data.scamRisk && data.aiProbability) {
        return data as AnalysisResult;
      }
    }
  } catch {
    // Silently capture any network/offline exceptions without uncaught console errors
  }

  // Step 2: Fallback to bulletproof local heuristic engine
  const modality = payload?.modality || 'text';
  const combinedText = [
    payload?.text || '',
    payload?.subject ? `Tiêu đề: ${payload.subject}` : '',
    payload?.sender ? `Người gửi: ${payload.sender}` : '',
    payload?.phoneNumber ? `SĐT: ${payload.phoneNumber}` : '',
    payload?.callerId ? `Caller ID: ${payload.callerId}` : '',
    payload?.url || '',
    payload?.transcript || '',
    payload?.videoTranscript || '',
  ]
    .filter(Boolean)
    .join('\n');

  const meta = {
    sender: payload?.sender,
    subject: payload?.subject,
    phoneNumber: payload?.phoneNumber,
    callerId: payload?.callerId,
    url: payload?.url,
    transcript: payload?.transcript || payload?.videoTranscript,
  };

  const localRes = analyzeLocally(modality, combinedText, meta);
  return formatLocalResultToAnalysisResult(localRes, payload);
}

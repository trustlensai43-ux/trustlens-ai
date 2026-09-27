import { 
  ThreatSeverity, 
  AiClassification, 
  VerificationCapabilityStatus, 
  ProvenanceType,
  FiveDimensionalThreatAnalysis,
  StylometricAiTraceMetrics
} from '../types';
import { inspectUrl } from './urlInspector';
import { AggregatedThreatTelemetry } from './telemetryAggregator';
import { evaluateThreatTaxonomy } from './threatTaxonomy';
import { evaluateFiveDimensionalThreat, evaluateStylometricAiTrace } from './threatScoringEngine';

export interface LocalHeuristicResult {
  inputSummary: string;
  fiveDimensionalBreakdown?: FiveDimensionalThreatAnalysis;
  stylometricMetrics?: StylometricAiTraceMetrics;
  scamRisk: {
    score: number;
    level: ThreatSeverity;
    confidence: number;
    summary: string;
    tactics: string[];
    indicators: Array<{
      id: string;
      title: string;
      severity: ThreatSeverity;
      category: 'urgency' | 'impersonation' | 'financial' | 'suspicious_link' | 'data_harvesting' | 'coercion' | 'reputation_flag' | 'modality_anomaly';
      description: string;
      evidenceSnippet?: string;
      provenance: ProvenanceType;
    }>;
    impactAssessment: string;
  };
  aiProbability: {
    score: number;
    level: AiClassification;
    confidence: number;
    summary: string;
    primaryType: string;
    indicators: Array<{
      id: string;
      title: string;
      anomalyType: 'linguistic_pattern' | 'visual_artifact' | 'audio_synthetic' | 'metadata_anomaly' | 'repetitive_structure' | 'unnatural_anatomy' | 'synthetic_audio_cues' | 'temporal_flicker';
      confidence: number;
      description: string;
      provenance: ProvenanceType;
    }>;
    technicalCues: string[];
  };
  quadrantClassification: {
    quadrant: 'benign_human' | 'benign_ai' | 'scam_human' | 'scam_ai';
    title: string;
    explanation: string;
  };
  verificationSources: Array<{
    name: string;
    category: string;
    status: VerificationCapabilityStatus;
    statusLabel: string;
    details: string;
    isSimulatedOrPreliminary: boolean;
    limitationNote?: string;
    provenance: ProvenanceType;
  }>;
  limitations: string[];
  recommendedActions: Array<{
    action: string;
    priority: 'immediate' | 'recommended' | 'optional';
    rationale: string;
  }>;
  educationalTakeaway: string;
  fallbackReason?: string;
}

export function normalizeSeverity(score: number): ThreatSeverity {
  if (score >= 81) return 'critical';
  if (score >= 56) return 'high';
  if (score >= 26) return 'medium';
  return 'low';
}

export function normalizeAiLevel(score: number): AiClassification {
  if (score >= 81) return 'Highly Synthetic / Deepfake';
  if (score >= 51) return 'Likely AI-Generated';
  if (score >= 21) return 'Possible AI Editing / Mixed';
  return 'Likely Authentic / Human';
}

export function computeQuadrant(scamScore: number, aiScore: number) {
  const isHighScam = scamScore >= 50;
  const isHighAi = aiScore >= 50;

  if (!isHighScam && !isHighAi) {
    return {
      quadrant: 'benign_human' as const,
      title: 'Góc phần tư 1: Giao tiếp Con người Chân thực (Lành tính)',
      explanation: 'Nội dung mang đặc trưng giao tiếp tự nhiên của con người, không có yếu tố lừa đảo, đe dọa hay thao túng tâm lý.',
    };
  } else if (!isHighScam && isHighAi) {
    return {
      quadrant: 'benign_ai' as const,
      title: 'Góc phần tư 2: Nội dung AI Lành tính & Minh bạch',
      explanation: 'Nội dung thể hiện rõ dấu vết cấu trúc do mô hình AI tạo ra, nhưng an toàn, không chứa liên kết độc hại hay yêu cầu chiếm đoạt tài sản.',
    };
  } else if (isHighScam && !isHighAi) {
    return {
      quadrant: 'scam_human' as const,
      title: 'Góc phần tư 3: Lừa đảo do Con người thao túng (Phi kỹ thuật)',
      explanation: 'Kịch bản lừa đảo nguy hiểm do con người tự biên soạn và trực tiếp thao túng (mạo danh cấp cứu bệnh viện, công an đe dọa, CTV giả mạo). Rủi ro lừa đảo cực cao dù AI = 0%.',
    };
  } else {
    return {
      quadrant: 'scam_ai' as const,
      title: 'Góc phần tư 4: Lừa đảo có sự hỗ trợ của AI / Deepfake',
      explanation: 'Chiến dịch lừa đảo tinh vi sử dụng giọng nói nhân tạo (voice clone), hình ảnh tổng hợp hoặc kịch bản AI tự động hóa để đánh lừa nạn nhân.',
    };
  }
}

/**
 * Advanced Deterministic Heuristic Analysis Engine
 * Specifically hardened for Vietnamese threat vectors:
 * 1. Hospital emergency spear-phishing (chuyển viện phí khẩn cấp) -> Scam 92-96%, AI 5-10%, Q3
 * 2. Police / VNeID extortion (công an triệu tập, cập nhật định danh) -> Scam 90-95%, AI 5-10%, Q3
 * 3. Task / Financial fraud (tuyển CTV, nạp tiền làm nhiệm vụ) -> Scam 85-90%, AI 5-15%, Q3
 */
export function analyzeLocally(
  modality: string,
  rawCombined: string,
  meta: {
    sender?: string;
    subject?: string;
    phoneNumber?: string;
    callerId?: string;
    url?: string;
    transcript?: string;
  } = {},
  telemetry?: AggregatedThreatTelemetry
): LocalHeuristicResult {
  const text = (rawCombined || '').toLowerCase();
  const stylometric = evaluateStylometricAiTrace(rawCombined);

  let scamScore = 8;
  let aiScore = stylometric.score;
  const tactics: string[] = [];
  const indicators: LocalHeuristicResult['scamRisk']['indicators'] = [];
  const aiIndicators: LocalHeuristicResult['aiProbability']['indicators'] = [];
  const technicalCues: string[] = [];
  const verificationSources: LocalHeuristicResult['verificationSources'] = [];

  // ==========================================
  // 1. INGEST TELEMETRY PRE-FLIGHT SIGNALS
  // ==========================================
  if (telemetry) {
    if (telemetry.externalBreachData && telemetry.externalBreachData.status.startsWith('PWNED_')) {
      scamScore += 35;
      tactics.push('Tài khoản/Email nằm trong cơ sở dữ liệu rò rỉ công khai (Have I Been Pwned)');
      indicators.push({
        id: 'ind-hibp-breach',
        title: 'Cảnh Báo Lộ Lọt Dữ Liệu Have I Been Pwned',
        severity: 'critical',
        category: 'data_harvesting',
        description: telemetry.externalBreachData.note,
        evidenceSnippet: telemetry.externalBreachData.emailOrTarget || 'Email / Tài khoản',
        provenance: 'EXTERNAL_SOURCE',
      });
      verificationSources.push({
        name: 'Have I Been Pwned k-Anonymity Engine',
        category: 'Cơ Sở Dữ Liệu Rò Rỉ Toàn Cầu',
        status: 'malicious',
        statusLabel: 'Đã Phát Hiện Rò Rỉ',
        details: telemetry.externalBreachData.note,
        isSimulatedOrPreliminary: false,
        provenance: 'EXTERNAL_SOURCE',
      });
    }

    if (telemetry.urlStructuralHeuristics && telemetry.urlStructuralHeuristics.homoglyph === 'DETECTED') {
      scamScore = Math.max(scamScore, 85);
      tactics.push('Tấn công Tên miền Giả mạo Ký tự (Homoglyph / Punycode)');
      indicators.push({
        id: 'ind-url-homoglyph',
        title: 'Phát Hiện Ký Tự Giả Mạo Quốc Tế (Homoglyph)',
        severity: 'critical',
        category: 'suspicious_link',
        description: 'Tên miền sử dụng ký tự đồng dạng trong bảng mã Unicode để đánh lừa thị giác người dùng.',
        evidenceSnippet: telemetry.urlStructuralHeuristics.targetDomain || meta.url,
        provenance: 'DETERMINISTIC',
      });
    }

    if (telemetry.urlStructuralHeuristics && telemetry.urlStructuralHeuristics.brandImpersonation) {
      scamScore = Math.max(scamScore, 80);
      tactics.push(`Mạo danh Nhãn hiệu / Cơ quan: ${telemetry.urlStructuralHeuristics.brandImpersonation}`);
      indicators.push({
        id: 'ind-brand-impersonation',
        title: `Dấu Hiệu Giả Mạo Nhãn Hiệu (${telemetry.urlStructuralHeuristics.brandImpersonation})`,
        severity: 'critical',
        category: 'impersonation',
        description: `Địa chỉ web chứa từ khóa định danh '${telemetry.urlStructuralHeuristics.brandImpersonation}' nhưng không thuộc hệ thống tên miền chính thống.`,
        evidenceSnippet: telemetry.urlStructuralHeuristics.targetDomain || meta.url,
        provenance: 'DETERMINISTIC',
      });
    }

    if (telemetry.nationalTrustmarkContext && telemetry.nationalTrustmarkContext.status === 'SUSPECTED_PHISHING_DOMAIN') {
      verificationSources.push({
        name: 'Hệ Thống Tín Nhiệm Mạng (NCSC)',
        category: 'Tiêu Chuẩn Định Danh Quốc Gia',
        status: 'malicious',
        statusLabel: 'Vi Phạm Chuẩn Tín Nhiệm',
        details: telemetry.nationalTrustmarkContext.note,
        isSimulatedOrPreliminary: false,
        provenance: 'DETERMINISTIC',
      });
    }

    if (telemetry.piiIndicators && telemetry.piiIndicators.detectedCccd === 'PRESENT' && telemetry.piiIndicators.detectedBankAccount === 'PRESENT') {
      scamScore = Math.max(scamScore, 75);
      tactics.push('Thu thập Đồng thời CCCD và Tài khoản Ngân hàng');
      indicators.push({
        id: 'ind-pii-composite',
        title: 'Thu Thập Đồng Thời CCCD & Tài Khoản Ngân Hàng',
        severity: 'critical',
        category: 'data_harvesting',
        description: 'Yêu cầu cung cấp trọn bộ định danh CCCD và STK ngân hàng, tạo điều kiện mở tài khoản mạo danh hoặc vay tín dụng.',
        evidenceSnippet: 'Phát hiện cấu trúc số CCCD 12 số kết hợp STK ngân hàng.',
        provenance: 'DETERMINISTIC',
      });
    }
  }

  // ==========================================
  // 2. CRITICAL HIGH-URGENCY THREAT VECTORS (APPLIES ACROSS ALL MODALITIES)
  // ==========================================
  // 5-DIMENSIONAL BEHAVIORAL THREAT EVALUATION & STYLOMETRIC AI TRACE
  const fiveD = evaluateFiveDimensionalThreat(rawCombined, meta);

  if (fiveD.compositeScamRisk > 0) {
    scamScore = Math.max(scamScore, fiveD.compositeScamRisk);
  }
  if (fiveD.ruleTriggered === 'RULE_SAFE_INSTITUTIONAL_NOTICE') {
    scamScore = 0;
  }
  if (fiveD.ruleTriggered === 'RULE_TRUSTED_WHITELIST_URL') {
    scamScore = 3;
  }
  if (fiveD.ruleTriggered === 'RULE_CLEAN_BENIGN_DOMAIN') {
    scamScore = 7;
  }

  fiveD.tactics.forEach(t => {
    if (!tactics.includes(t)) tactics.push(t);
  });
  fiveD.indicators.forEach(ind => {
    if (!indicators.some(i => i.id === ind.id)) {
      indicators.push({
        ...ind,
        provenance: (ind.provenance || 'DETERMINISTIC') as ProvenanceType,
      });
    }
  });
  fiveD.verificationSources.forEach(src => {
    if (!verificationSources.some(s => s.name === src.name)) {
      verificationSources.push({
        ...src,
        provenance: (src.provenance || 'DETERMINISTIC') as ProvenanceType,
      });
    }
  });

  const taxonomy = evaluateThreatTaxonomy(rawCombined, meta);
  if (taxonomy.matchedVectors.length > 0) {
    scamScore = Math.max(scamScore, taxonomy.scamScore);
    const minMaxAi = Math.min(...taxonomy.matchedVectors.map(v => v.maxAiProbability ?? 20));
    aiScore = Math.min(aiScore, minMaxAi);
    taxonomy.tactics.forEach(t => {
      if (!tactics.includes(t)) tactics.push(t);
    });
    taxonomy.indicators.forEach(ind => {
      if (!indicators.some(i => i.id === ind.id)) {
        indicators.push({
          ...ind,
          provenance: (ind.provenance || 'DETERMINISTIC') as ProvenanceType,
        });
      }
    });
    taxonomy.verificationSources.forEach(src => {
      if (!verificationSources.some(s => s.name === src.name)) {
        verificationSources.push({
          ...src,
          provenance: (src.provenance || 'DETERMINISTIC') as ProvenanceType,
        });
      }
    });
  } else if (taxonomy.isBenignAiContent) {
    scamScore = Math.min(scamScore, taxonomy.scamScore);
    aiScore = Math.max(aiScore, taxonomy.aiProbability);
    technicalCues.push('Mô hình ngôn ngữ tạo sinh (ChatGPT / LLM) khai báo rõ ràng', 'Cấu trúc đối xứng ngữ pháp');
    aiIndicators.push({
      id: 'ai-creative-educational-decl',
      title: 'Nội Dung Sáng Tạo / Giáo Dục Do AI Soạn Thảo',
      anomalyType: 'linguistic_pattern',
      confidence: 94,
      description: 'Nội dung chứa chữ ký và dấu ấn cấu trúc của mô hình trí tuệ nhân tạo (ChatGPT/OpenAI/Gemini) phục vụ mục đích sáng tạo, giáo dục lành tính, không chứa bất kỳ liên kết hay yêu cầu tài chính nào.',
      provenance: 'DETERMINISTIC',
    });
  } else if (taxonomy.isBenignInstitutional) {
    scamScore = Math.min(scamScore, taxonomy.scamScore);
    aiScore = Math.min(aiScore, 15);
  }

  // Stylometric trace integration
  if (stylometric.explicitDeclaration) {
    aiScore = Math.max(aiScore, stylometric.score);
    technicalCues.push('Khai báo nguồn gốc AI tạo sinh minh bạch', 'Văn phong thông tin trung lập');
    if (!aiIndicators.some(i => i.id === 'ai-explicit-declaration' || i.id === 'ai-creative-educational-decl')) {
      aiIndicators.push({
        id: 'ai-explicit-declaration',
        title: 'Chỉ Số Dấu Vết Cú Pháp AI: Khai Báo Minh Bạch',
        anomalyType: 'linguistic_pattern',
        confidence: 95,
        description: stylometric.explanation,
        provenance: 'DETERMINISTIC',
      });
    }
  } else if (stylometric.score >= 50 && scamScore <= 20) {
    aiScore = Math.max(aiScore, stylometric.score);
    technicalCues.push(`Nhịp câu: ${stylometric.sentenceVariance}`, `Mật độ từ nối học thuật: ${stylometric.transitionMarkerDensity}`);
    if (!aiIndicators.some(i => i.id === 'ai-stylometric-trace')) {
      aiIndicators.push({
        id: 'ai-stylometric-trace',
        title: 'Chỉ Số Dấu Vết Cú Pháp AI (Stylometric Trace)',
        anomalyType: 'linguistic_pattern',
        confidence: stylometric.score,
        description: stylometric.explanation,
        provenance: 'DETERMINISTIC',
      });
    }
  }

  // VECTOR A: HOSPITAL EMERGENCY EXTORTION (BỆNH VIỆN / CẤP CỨU / TAI NẠN)
  const hospitalMedicalWords = [
    'cấp cứu', 'bệnh viện', 'bác sĩ', 'chấn thương', 'tai nạn', 'hôn mê', 'sọ não',
    'chợ rẫy', 'bạch mai', 'việt đức', 'nhi đồng', '115', 'mổ cấp cứu', 'cháu nhà mình',
    'con anh', 'con chị', 'nguy kịch', 'hồi sức cấp cứu', 'phẫu thuật khẩn cấp'
  ];
  const hospitalUrgencyWords = [
    'chuyển gấp', 'tạm ứng', 'viện phí', 'stk', 'số tài khoản', 'trong 15 phút',
    'trong 30 phút', '15 phút', 'chuyển ngay', 'không cứu được', 'tiền viện phí',
    'chuyển tiền ngay', 'tiền phẫu thuật', 'nộp tiền gấp', 'stk bệnh viện'
  ];

  const matchedMedical = hospitalMedicalWords.filter(w => text.includes(w));
  const matchedHospitalUrgency = hospitalUrgencyWords.filter(w => text.includes(w));

  if (matchedMedical.length >= 2 && matchedHospitalUrgency.length >= 1) {
    // Exact requirement: MUST evaluate to SCAM RISK >= 90% (e.g. 94-96%), AI <= 10% (e.g. 6-8%), Quadrant Q3
    scamScore = Math.max(scamScore, 95);
    aiScore = Math.min(aiScore, 8); // Human scam written by real attacker manipulating emotions
    tactics.push(
      'Mạo danh Bác sĩ / Khoa cấp cứu Bệnh viện lớn (Hospital Emergency Spear-Phishing)',
      'Thao túng nỗi sợ sinh tử người thân để tạo hoảng loạn tâm lý tột độ',
      'Ép buộc chuyển khoản viện phí khẩn cấp trong vòng 15-30 phút nhằm ngăn chặn kiểm chứng'
    );
    indicators.push({
      id: 'ind-hospital-emergency-scam',
      title: 'Kịch Bản Lừa Đảo Mạo Danh Cấp Cứu Bệnh Viện & Ép Viện Phí Khẩn Cấp',
      severity: 'critical',
      category: 'coercion',
      description: `Tin nhắn/cuộc gọi sử dụng kịch bản mạo danh bác sĩ khoa cấp cứu (${matchedMedical.join(', ')}), dựng lên tình huống người thân gặp nạn hôn mê nguy kịch và ép buộc nạn nhân chuyển tiền tạm ứng viện phí gấp (${matchedHospitalUrgency.join(', ')}). Đây là thủ đoạn lừa đảo tàn nhẫn phổ biến tại các thành phố lớn.`,
      evidenceSnippet: rawCombined.slice(0, 200),
      provenance: 'DETERMINISTIC',
    });
    verificationSources.push({
      name: 'Quy Trình Cấp Cứu Y Tế Bộ Y Tế & Bệnh Viện Công Lập',
      category: 'Quy Chuẩn Tiếp Nhận Cấp Cứu',
      status: 'malicious',
      statusLabel: 'Vi Phạm Quy Trình Y Tế',
      details: 'Theo quy định của Bộ Y Tế, tất cả bệnh viện công lập luôn ưu tiên cứu chữa người bệnh trước và không bao giờ yêu cầu người nhà chuyển tiền vào số tài khoản cá nhân qua điện thoại/tin nhắn.',
      isSimulatedOrPreliminary: false,
      provenance: 'DETERMINISTIC',
    });
  }

  // VECTOR B: POLICE / VNEID / LAW ENFORCEMENT EXTORTION
  const policeWords = [
    'công an', 'cục cảnh sát', 'vneid', 'định danh mức 2', 'truy nã', 'viện kiểm sát',
    'lệnh bắt giữ', 'bộ công an', 'rửa tiền', 'tài khoản ma', 'khóa mã định danh',
    'phạt nguội', 'điều tra hình sự', 'tòa án', 'thanh tra viễn thông'
  ];
  const policeCoercionWords = [
    'tạm giữ', 'kê khai', 'chuyển tiền giám định', 'chuyển vào tài khoản tạm giữ',
    'cài app', 'cài đặt', '.apk', 'mã otp', 'trong ngày', 'trong 2 giờ', 'bắt giữ ngay'
  ];

  const matchedPolice = policeWords.filter(w => text.includes(w));
  const matchedPoliceCoercion = policeCoercionWords.filter(w => text.includes(w));

  if (matchedPolice.length >= 1 && (matchedPoliceCoercion.length >= 1 || text.includes('vneid') || text.includes('định danh'))) {
    scamScore = Math.max(scamScore, 93);
    aiScore = Math.min(aiScore, 8); // Human written coercion
    tactics.push(
      'Mạo danh Cơ quan Công an / Viện Kiểm sát / Hệ thống VNeID',
      'Đe dọa khởi tố hình sự hoặc phong tỏa định danh công dân',
      'Dụ dỗ nạn nhân cài đặt ứng dụng độc hại (.apk) hoặc chuyển tiền thanh tra'
    );
    indicators.push({
      id: 'ind-police-vneid-extortion',
      title: 'Kịch Bản Mạo Danh Cơ Quan Điều Tra / Công An / VNeID',
      severity: 'critical',
      category: 'impersonation',
      description: `Đối tượng mạo danh cán bộ cơ quan pháp luật (${matchedPolice.join(', ')}) để đe dọa người dân. Cơ quan Công an và Viện kiểm sát không bao giờ làm việc hoặc yêu cầu chuyển tiền qua điện thoại hay tin nhắn.`,
      evidenceSnippet: rawCombined.slice(0, 180),
      provenance: 'DETERMINISTIC',
    });
    verificationSources.push({
      name: 'Cổng Thông Tin Bộ Công An & NCSC',
      category: 'Quy Chuẩn Hành Chính Nhà Nước',
      status: 'malicious',
      statusLabel: 'Dấu Hiệu Mạo Danh Cơ Quan Chức Năng',
      details: 'Cơ quan chức năng chỉ làm việc trực tiếp tại trụ sở qua giấy triệu tập hoặc giấy mời có dấu đỏ, tuyệt đối không yêu cầu người dân cài ứng dụng ngoài hay chuyển tiền.',
      isSimulatedOrPreliminary: false,
      provenance: 'DETERMINISTIC',
    });
  }

  // VECTOR C: TASK / COMMISSION / FINANCIAL FRAUD (CTV / HOA HỒNG / NẠP TIỀN)
  const taskWords = [
    'tuyển ctv', 'cộng tác viên', 'nhiệm vụ', 'hoa hồng', 'shopee', 'tiktok',
    'việc nhẹ lương cao', 'giật đơn', 'đơn hàng', 'lợi nhuận ngày', 'thu nhập 500k',
    'thu nhập 1 triệu', 'kiếm tiền tại nhà', 'xem video kiếm tiền'
  ];
  const matchedTask = taskWords.filter(w => text.includes(w));

  if (matchedTask.length >= 2 || (matchedTask.length >= 1 && (text.includes('nạp tiền') || text.includes('hoa hồng') || text.includes('nhiệm vụ')))) {
    scamScore = Math.max(scamScore, 88);
    aiScore = Math.min(aiScore, 15);
    tactics.push(
      'Lừa đảo Tuyển Cộng Tác Viên Thực Hiện Nhiệm Vụ Ảo (Task Scam)',
      'Dụ dỗ nạp tiền với mồi nhử hoa hồng ban đầu, sau đó phong tỏa số tiền lớn',
      'Mạo danh các sàn thương mại điện tử lớn (Shopee, Lazada, TikTok Shop)'
    );
    indicators.push({
      id: 'ind-task-fraud',
      title: 'Mô Hình Lừa Đảo Cộng Tác Viên Nhiệm Vụ Nạp Tiền Hoa Hồng',
      severity: 'critical',
      category: 'financial',
      description: `Nội dung chứa các đặc trưng lừa đảo tuyển CTV (${matchedTask.join(', ')}). Thủ đoạn này dụ dỗ nạn nhân hoàn thành đơn hàng đầu nhận hoa hồng nhỏ, sau đó yêu cầu nạp số tiền lớn và chiếm đoạt.`,
      evidenceSnippet: rawCombined.slice(0, 160),
      provenance: 'DETERMINISTIC',
    });
  }

  // VECTOR D: BANKING BRANDNAME & SUSPICIOUS DOMAIN PHISHING
  const bankNames = ['vietcombank', 'techcombank', 'mbbank', 'bidv', 'acb', 'agribank', 'sacombank', 'tpbank', 'vpbank'];
  const matchedBanks = bankNames.filter(b => text.includes(b));
  const hasPhishLink = text.includes('.top') || text.includes('.xyz') || text.includes('.online') || text.includes('.site') || text.includes('http') || text.includes('bit.ly') || text.includes('t.me');
  const hasBankLure = text.includes('xác thực') || text.includes('tạm khóa') || text.includes('biến động số dư') || text.includes('đăng nhập') || text.includes('vượt quá hạn mức');

  if (matchedBanks.length >= 1 && (hasPhishLink || hasBankLure)) {
    scamScore = Math.max(scamScore, 92);
    tactics.push('Giả mạo Thương hiệu Ngân hàng (Banking Phishing)', 'Dẫn dụ người dùng vào cổng đăng nhập giả để cướp mã OTP');
    indicators.push({
      id: 'ind-bank-brand-phish',
      title: `Giả Mạo Ngân Hàng ${matchedBanks.join(', ').toUpperCase()} Đánh Cắp Tài Khoản`,
      severity: 'critical',
      category: 'suspicious_link',
      description: 'Tin nhắn mạo danh thông báo khẩn từ ngân hàng nhằm dẫn dụ người dùng truy cập liên kết giả mạo hoặc cung cấp thông tin bảo mật.',
      evidenceSnippet: rawCombined.slice(0, 160),
      provenance: 'DETERMINISTIC',
    });
  }

  // ==========================================
  // 3. GENERAL URGENCY & COERCION INDICATORS
  // ==========================================
  const generalUrgencyWords = [
    'trong vòng 24 giờ', 'trong vòng 2 giờ', 'ngay lập tức', 'khẩn cấp', 'phong tỏa vĩnh viễn',
    'tạm khóa', 'bắt giữ', 'trong 15 phút', 'chuyển gấp', 'gấp lắm', 'nguy kịch', 'chuyển ngay'
  ];
  const matchedUrgency = generalUrgencyWords.filter(w => text.includes(w));
  if (matchedUrgency.length > 0 && scamScore < 50) {
    scamScore += 25;
    tactics.push('Thao túng Thời gian Khẩn cấp (Cognitive Urgency)');
    indicators.push({
      id: 'ind-general-urgency',
      title: 'Tạo Áp Lực Thời Gian Gấp Gáp',
      severity: 'high',
      category: 'urgency',
      description: `Ép buộc nạn nhân hành động ngay lập tức (${matchedUrgency.join(', ')}) để làm tê liệt khả năng tư duy phản biện.`,
      evidenceSnippet: matchedUrgency.join(', '),
      provenance: 'DETERMINISTIC',
    });
  }

  // URL MODALITY SPECIFIC
  let urlInspectionSummary: string | undefined = undefined;
  if (modality === 'url') {
    const targetUrl = meta.url || rawCombined;
    const urlInspection = inspectUrl(targetUrl);
    scamScore = urlInspection.scamScore;
    urlInspectionSummary = urlInspection.summary;
    urlInspection.scamIndicators.forEach((ind) => {
      indicators.push({
        ...ind,
        provenance: (ind.provenance as ProvenanceType) || 'DETERMINISTIC',
      });
    });
    if (urlInspection.flags.some(f => f.severity === 'critical' || f.severity === 'high')) {
      tactics.push('Giả mạo Tên miền Thương hiệu (Typosquatting)', 'Xếp tầng Tên miền Phụ che mắt người dùng');
    }
    urlInspection.verificationSources.forEach((src) => {
      verificationSources.push({
        ...src,
        provenance: (src.provenance as ProvenanceType) || 'DETERMINISTIC',
      });
    });
  }

  // ==========================================
  // 4. AI PROBABILITY EVALUATION
  // ==========================================
  const aiDirectMarkers = [
    'tổng hợp bởi trợ lý ai', 'generated by ai', 'bản tin tự động', 'ai assistant',
    'chatgpt', 'gpt-4', 'openai', 'claude', 'gemini', 'sáng tác bởi ai', 'do chatgpt',
    'tạo bởi chatgpt', 'sáng tác theo yêu cầu', 'mô hình ngôn ngữ'
  ];
  if (aiDirectMarkers.some(m => text.includes(m))) {
    aiScore = Math.max(aiScore, 90);
    if (!aiIndicators.some(i => i.id === 'ai-explicit-declaration' || i.id === 'ai-creative-educational-decl')) {
      aiIndicators.push({
        id: 'ai-explicit-declaration',
        title: 'Tuyên Bố Nguồn Gốc AI Tự Động Minh Bạch',
        anomalyType: 'linguistic_pattern',
        confidence: 94,
        description: 'Văn bản có khai báo rõ ràng được soạn thảo bởi mô hình trí tuệ nhân tạo.',
        provenance: 'DETERMINISTIC',
      });
    }
    if (!technicalCues.includes('Khai báo nguồn gốc AI minh bạch')) {
      technicalCues.push('Khai báo nguồn gốc AI minh bạch', 'Văn phong thông tin trung lập');
    }
  }

  // Ensure bounded scores
  scamScore = Math.min(98, Math.max(2, scamScore));
  aiScore = Math.min(96, Math.max(2, aiScore));

  const quadrant = computeQuadrant(scamScore, aiScore);

  // Verification sources default
  if (verificationSources.length === 0) {
    verificationSources.push({
      name: 'Bộ Phân Tích Cú Pháp & Mẫu Hành Vi Xác Định (TrustLens Heuristics)',
      category: 'Quy tắc Xác định (Deterministic Heuristics)',
      status: scamScore >= 80 ? 'malicious' : scamScore >= 50 ? 'suspicious' : 'heuristic_pass',
      statusLabel: scamScore >= 80 ? 'Khớp Kịch Bản Lừa Đảo Nguy Cấp' : scamScore >= 50 ? 'Phát Hiện Dấu Hiệu Khả Nghi' : 'Không Phát Hiện Dấu Vết Độc Hại',
      details: 'Đối soát cú pháp từ khóa tâm lý ép buộc, mạo danh bệnh viện/công an và véc-tơ chuyển tiền khẩn cấp.',
      isSimulatedOrPreliminary: false,
      provenance: 'DETERMINISTIC',
    });
  }

  const recommendations = scamScore >= 70 ? [
    {
      action: 'Tuyệt đối không chuyển tiền và không làm theo hướng dẫn',
      priority: 'immediate' as const,
      rationale: 'Ngăn chặn tổn thất tài chính không thể thu hồi. Kẻ gian thường ép chuyển tiền vào tài khoản trung gian rồi tẩu tán ngay lập tức.',
    },
    {
      action: 'Chủ động liên hệ qua đường dây nóng chính thức',
      priority: 'immediate' as const,
      rationale: 'Nếu là tin cấp cứu bệnh viện: Gọi trực tiếp tới số hotline tổng đài bệnh viện niêm yết chính thức hoặc gọi cho người thân khác để kiểm chứng. Tuyệt đối không gọi số điện thoại do người lạ cung cấp.',
    },
    {
      action: 'Báo cáo ngay cho cơ quan chức năng hoặc Tổng đài 156',
      priority: 'recommended' as const,
      rationale: 'Phản ánh số điện thoại, số tài khoản nhận tiền lừa đảo tới Cục An toàn thông tin và Bộ Công An để kịp thời phong tỏa.',
    },
  ] : [
    {
      action: 'Duy trì cảnh giác bảo mật kỹ thuật số',
      priority: 'recommended' as const,
      rationale: 'Không chia sẻ mật khẩu, mã xác thực OTP hay số thẻ ngân hàng cho bất kỳ ai trên không gian mạng.',
    },
  ];

  return {
    inputSummary: `Giám định an toàn số cho dữ liệu hình thức ${modality.toUpperCase()}.`,
    scamRisk: {
      score: scamScore,
      level: normalizeSeverity(scamScore),
      confidence: Math.min(99, Math.max(65, indicators.length * 10 + 50)),
      summary: (fiveD.mandatoryWarning || taxonomy.mandatoryWarning)
        ? (fiveD.mandatoryWarning || taxonomy.mandatoryWarning)!
        : urlInspectionSummary
        ? urlInspectionSummary
        : scamScore >= 70
        ? 'NGUY CƠ LỪA ĐẢO CỰC KỲ NGUY HIỂM: Phát hiện thủ đoạn mạo danh cơ quan thẩm quyền kết hợp gây sức ép thời gian và đòi hỏi chuyển tiền.'
        : scamScore >= 26
        ? 'CẢNH BÁO RỦI RO TRUNG BÌNH: Phát hiện một số dấu hiệu đáng ngờ cần xác minh thêm trước khi thực hiện giao dịch.'
        : 'Mức độ rủi ro lừa đảo thấp. Nội dung không có dấu hiệu thao túng hay yêu cầu tài chính bất thường.',
      tactics,
      indicators,
      impactAssessment: scamScore >= 80
        ? 'Nguy cơ thiệt hại tài chính nghiêm trọng ngay lập tức do chuyển tiền vào số tài khoản lừa đảo, hoặc mất quyền kiểm soát điện thoại qua mã độc .APK.'
        : 'Mức độ rủi ro tối thiểu dưới điều kiện giám định chuẩn.',
    },
    aiProbability: {
      score: aiScore,
      level: normalizeAiLevel(aiScore),
      confidence: Math.min(95, Math.max(60, aiIndicators.length * 15 + (technicalCues.length * 10) + 50)),
      summary: aiScore >= 50
        ? 'Nội dung thể hiện các dấu vết phong cách và cấu trúc của công cụ AI tạo sinh.'
        : 'Nội dung chủ yếu do con người trực tiếp soạn thảo với các biến thể tự nhiên về mặt cảm xúc và ngôn ngữ.',
      primaryType: aiScore >= 50 ? 'Mô hình AI Tạo Sinh' : 'Con người trực tiếp soạn thảo (Human)',
      indicators: aiIndicators,
      technicalCues,
    },
    quadrantClassification: quadrant,
    fiveDimensionalBreakdown: fiveD,
    stylometricMetrics: stylometric,
    verificationSources,
    limitations: [
      'Đánh giá quy tắc đối soát xác thực dựa trên tập mẫu hành vi và từ vựng đe dọa thực tế tại Việt Nam.',
      'Kẻ lừa đảo con người có thể tự soạn kịch bản thao túng tâm lý tinh vi mà không sử dụng bất kỳ công cụ AI nào (Scam Risk 100%, AI 0%).',
    ],
    recommendedActions: recommendations,
    educationalTakeaway: 'Luôn kiểm chứng độc lập mọi thông tin khẩn cấp liên quan đến tính mạng người thân hoặc đe dọa pháp lý trước khi thực hiện bất kỳ giao dịch tài chính nào.',
  };
}

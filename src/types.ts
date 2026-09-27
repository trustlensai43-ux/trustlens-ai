export type ModalityType = 'text' | 'email' | 'phone' | 'url' | 'image' | 'video';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export type AiClassification = 
  | 'Likely Authentic / Human'
  | 'Possible AI Editing / Mixed'
  | 'Likely AI-Generated'
  | 'Highly Synthetic / Deepfake';

export type ProvenanceType = 'DETERMINISTIC' | 'AI_HEURISTIC' | 'EXTERNAL_SOURCE' | 'UNAVAILABLE';

export interface ScamIndicator {
  id: string;
  title: string;
  severity: ThreatSeverity;
  category: 'urgency' | 'impersonation' | 'financial' | 'suspicious_link' | 'data_harvesting' | 'coercion' | 'reputation_flag' | 'modality_anomaly';
  description: string;
  evidenceSnippet?: string;
  provenance?: ProvenanceType;
}

export interface AiIndicator {
  id: string;
  title: string;
  anomalyType: 'linguistic_pattern' | 'visual_artifact' | 'audio_synthetic' | 'metadata_anomaly' | 'repetitive_structure' | 'unnatural_anatomy' | 'synthetic_audio_cues' | 'temporal_flicker';
  confidence: number; // 0 to 100
  description: string;
  provenance?: ProvenanceType;
}

export type VerificationCapabilityStatus = 
  | 'verified_format' 
  | 'heuristic_pass'
  | 'suspicious' 
  | 'malicious' 
  | 'offline_heuristic'
  | 'preliminary_inspection'
  | 'unavailable_no_live_feed';

export interface VerificationSource {
  name: string;
  category: string;
  status: VerificationCapabilityStatus;
  statusLabel: string;
  details: string;
  isSimulatedOrPreliminary: boolean;
  limitationNote?: string;
  referenceUrl?: string;
  provenance?: ProvenanceType;
}

export interface RecommendedAction {
  action: string;
  priority: 'immediate' | 'recommended' | 'optional';
  rationale: string;
}

export interface MethodologyBreakdown {
  deterministicChecks: string[];
  extractedEvidence: string[];
  aiReasoning: string[];
  unconnectedTelemetry: string[];
  modelReasoning?: string;
  deterministicHeuristics?: string;
  externalRegistries?: string;
  limitationsDisclaimer?: string;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  modality: ModalityType;
  inputSummary: string;
  engineUsed: 'gemini_multimodal' | 'LOCAL_FALLBACK';
  analysisMode?: string;
  fallbackReason?: string | null;
  inputMetadata?: {
    sender?: string;
    subject?: string;
    phoneNumber?: string;
    callerId?: string;
    url?: string;
    fileName?: string;
    fileSize?: number;
    mediaType?: string;
    previewDataUrl?: string;
    rawLength?: number;
  };
  scamRisk: {
    score: number; // 0-100
    level: ThreatSeverity;
    confidence: number; // 0-100
    summary: string;
    tactics: string[];
    indicators: ScamIndicator[];
    impactAssessment: string;
  };
  aiProbability: {
    score: number; // 0-100
    level: AiClassification;
    confidence: number; // 0-100
    summary: string;
    primaryType: string;
    indicators: AiIndicator[];
    technicalCues: string[];
  };
  quadrantClassification: {
    quadrant: 'benign_human' | 'benign_ai' | 'scam_human' | 'scam_ai';
    title: string;
    explanation: string;
  };
  methodologyBreakdown?: MethodologyBreakdown;
  verificationSources: VerificationSource[];
  threatTelemetry?: ThreatTelemetry;
  fiveDimensionalBreakdown?: FiveDimensionalThreatAnalysis;
  stylometricMetrics?: StylometricAiTraceMetrics;
  limitations: string[];
  recommendedActions: RecommendedAction[];
  educationalTakeaway: string;
  rawInputSnippet?: string;
}

export interface ThreatDimensionScore {
  dimensionId: 'coercion' | 'financial' | 'malware' | 'impersonation' | 'harvesting';
  name: string;
  weight: number;
  score: number; // 0 to 100
  matchedCount: number;
  signals: string[];
  explanation: string;
}

export interface FiveDimensionalThreatAnalysis {
  dimensions: {
    coercion: ThreatDimensionScore;
    financial: ThreatDimensionScore;
    malware: ThreatDimensionScore;
    impersonation: ThreatDimensionScore;
    harvesting: ThreatDimensionScore;
  };
  compositeScamRisk: number;
  threatSeverity: ThreatSeverity;
  ruleTriggered?: string;
  detectedFlagsSummary: string;
  indicators: ScamIndicator[];
  tactics: string[];
  verificationSources: VerificationSource[];
  mandatoryWarning?: string;
}

export interface StylometricAiTraceMetrics {
  score: number; // 0 to 100
  sentenceVariance: 'uniform_machine' | 'natural_human' | 'mixed';
  transitionMarkerDensity: 'high' | 'moderate' | 'low';
  emotionalNoiseLevel: 'none_machine' | 'natural_human' | 'elevated';
  explicitDeclaration: boolean;
  detectedMarkers: string[];
  explanation: string;
}

export interface ThreatTelemetry {
  xmlEnvelope: string;
  externalBreachData: {
    source: string;
    status: string;
    note: string;
    pwnedCount?: number;
    emailOrTarget?: string;
    sha1Prefix?: string;
    confidence?: number;
    summary?: string;
  };
  deterministicTechnicalSignatures?: {
    summary?: string;
    findings?: any[];
  };
  preAnalysisHeuristicRisk?: {
    preliminaryScamScore?: number;
    rationale?: string;
  };
  urlStructuralHeuristics: {
    homoglyph: 'DETECTED' | 'NOT_DETECTED';
    punycode: 'DETECTED' | 'NOT_DETECTED';
    port: string;
    subdomainStacking: string;
    tldRisk: 'HIGH' | 'MODERATE' | 'LOW' | 'BENIGN';
    brandImpersonation?: string;
    targetDomain?: string;
  };
  piiIndicators: {
    detectedCccd: 'PRESENT' | 'NONE';
    cccdCount?: number;
    detectedBankAccount: 'PRESENT' | 'NONE';
    detectedCards: 'PRESENT' | 'NONE';
    urgencyLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'NONE';
    phoneCarrier?: string;
    carrierPrefix?: string;
  };
  nationalTrustmarkContext: {
    registry: string;
    status: string;
    note: string;
    matchedBrandOrEntity?: string;
  };
  timestamp?: string;
}

export interface SampleCase {
  id: string;
  title: string;
  modality: ModalityType;
  type: 'suspicious' | 'benign_human' | 'benign_ai';
  description: string;
  badge: string;
  sampleData: {
    text?: string;
    sender?: string;
    subject?: string;
    body?: string;
    phoneNumber?: string;
    callerId?: string;
    transcript?: string;
    url?: string;
    imageSampleUrl?: string;
    imageTitle?: string;
    videoTitle?: string;
    videoTranscript?: string;
  };
  expectedScamRisk: number;
  expectedAiProb: number;
  learningFocus: string;
}

export interface ReportingResource {
  id: string;
  countryCode: 'VN' | 'US' | 'UK' | 'CA' | 'AU' | 'EU' | 'GLOBAL';
  countryName: string;
  flagEmoji: string;
  agencyName: string;
  portalName: string;
  url: string;
  hotline?: string;
  description: string;
  scope: string;
  submissionTypes: string[];
}

export interface PiiExposureItem {
  type: string;
  label: string;
  snippet: string;
  severity: ThreatSeverity;
  riskReason: string;
}

export interface CompositeAttackVector {
  vector: string;
  explanation: string;
  severity: ThreatSeverity;
  targetedThreats: string[];
}

export interface ExposureAuditResult {
  riskScore: number; // 0 - 100
  riskLevel: ThreatSeverity;
  detectedPiiItems: PiiExposureItem[];
  compositeAttackVectors: CompositeAttackVector[];
  recommendations: string[];
  provenance: 'AI_HEURISTIC';
  summary: string;
  timestamp: string;
}

export interface CredentialBreachResult {
  status: 'safe' | 'compromised' | 'error';
  pwnedCount: number;
  sha1Prefix: string;
  sha1Suffix: string;
  provenance: 'EXTERNAL_SOURCE';
  source: string;
  message: string;
  timestamp: string;
}

export interface EmailBreachIncident {
  name: string;
  domain: string;
  breachDate: string;
  compromisedData: string[];
  severity: ThreatSeverity;
  description: string;
}

export interface EmailBreachReport {
  email: string;
  domain: string;
  status: 'safe' | 'breached';
  breachCount: number;
  incidents: EmailBreachIncident[];
  domainClassification: {
    domainType: 'public_webmail' | 'corporate' | 'education' | 'government' | 'custom';
    label: string;
    description: string;
    credentialStuffingRisk: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
    riskScore: number;
  };
  aiThreatSynthesis: string;
  timestamp: string;
}

export interface PhoneBreachReport {
  phoneNumber: string;
  formattedNumber: string;
  carrier: {
    name: string;
    prefix: string;
    mnpDisclaimer: string;
  };
  exposureRisk: {
    level: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
    score: number;
    title: string;
    description: string;
    knownSources: string[];
  };
  simSwapDefense: {
    riskFactors: string[];
    guidelines: Array<{
      title: string;
      description: string;
      action: string;
    }>;
  };
  timestamp: string;
}


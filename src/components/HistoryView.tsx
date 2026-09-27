import React from 'react';
import { ScanHistoryView } from './ScanHistoryView';
import { AnalysisResult } from '../types';

export interface HistoryViewProps {
  history: AnalysisResult[];
  onSelectScan: (scan: AnalysisResult) => void;
  onClearHistory: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = (props) => {
  return <ScanHistoryView {...props} />;
};

export default HistoryView;

import { Finding, FindingCategory } from './finding.js';
import { Severity } from './severity.js';

export interface ReportSummary {
  totalFiles: number;
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<FindingCategory, number>;
  executionTimeMs: number;
}

export interface ReportMetadata {
  agentVersion: string;
  analyzedAt: string;
  configUsed: string;
}

export interface AnalysisReport {
  summary: ReportSummary;
  findings: Finding[];
  metadata: ReportMetadata;
}

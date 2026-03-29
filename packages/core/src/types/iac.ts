import { Severity } from './severity.js';

export interface IaCResource {
  type: string;
  name: string;
  properties: Record<string, unknown>;
  file: string;
  lineStart: number;
  lineEnd: number;
}

export interface ComplianceFrameworkRef {
  framework: 'CIS' | 'PCI-DSS' | 'HIPAA' | 'NIST';
  control: string;
  description?: string;
}

export interface RemediationGuide {
  description: string;
  code?: string;
  references: string[];
}

export interface ComplianceViolation {
  id: string;
  rule: string;
  severity: Severity;
  resource: {
    type: string;
    name: string;
    file: string;
    line: number;
  };
  description: string;
  impact: string;
  remediation: RemediationGuide;
  compliance: ComplianceFrameworkRef[];
}

export interface ComplianceReportSummary {
  totalResources: number;
  totalViolations: number;
  complianceScore: number;
  bySeverity: Record<Severity, number>;
  byResourceType: Record<string, number>;
  executionTimeMs: number;
}

export interface ComplianceReport {
  summary: ComplianceReportSummary;
  violations: ComplianceViolation[];
  recommendations: string[];
  metadata: {
    agentVersion: string;
    analyzedAt: string;
    frameworks: string[];
  };
}

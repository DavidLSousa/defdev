import { Finding, FindingCategory } from '../types/finding.js';
import { Severity } from '../types/severity.js';
import { AnalysisReport, ReportMetadata } from '../types/analysis-report.js';

const EMPTY_SEVERITY_COUNTS = (): Record<Severity, number> => ({
  [Severity.CRITICAL]: 0,
  [Severity.HIGH]: 0,
  [Severity.MEDIUM]: 0,
  [Severity.LOW]: 0,
  [Severity.INFO]: 0,
});

const EMPTY_CATEGORY_COUNTS = (): Record<FindingCategory, number> => ({
  [FindingCategory.INJECTION]: 0,
  [FindingCategory.SECRETS_EXPOSURE]: 0,
  [FindingCategory.INSECURE_DEPENDENCIES]: 0,
  [FindingCategory.AUTH_ISSUES]: 0,
  [FindingCategory.CRYPTO_ISSUES]: 0,
  [FindingCategory.MISCONFIGURATION]: 0,
});

export function buildReport(
  findings: Finding[],
  totalFiles: number,
  executionTimeMs: number,
  metadata: Partial<ReportMetadata> = {}
): AnalysisReport {
  const bySeverity = EMPTY_SEVERITY_COUNTS();
  const byCategory = EMPTY_CATEGORY_COUNTS();

  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }

  return {
    summary: {
      totalFiles,
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      executionTimeMs,
    },
    findings: findings.sort((a, b) => {
      const severityDiff =
        (b.severity === Severity.CRITICAL ? 4 : b.severity === Severity.HIGH ? 3 : b.severity === Severity.MEDIUM ? 2 : b.severity === Severity.LOW ? 1 : 0) -
        (a.severity === Severity.CRITICAL ? 4 : a.severity === Severity.HIGH ? 3 : a.severity === Severity.MEDIUM ? 2 : a.severity === Severity.LOW ? 1 : 0);
      return severityDiff !== 0 ? severityDiff : a.file.localeCompare(b.file);
    }),
    metadata: {
      agentVersion: metadata.agentVersion ?? '1.0.0',
      analyzedAt: metadata.analyzedAt ?? new Date().toISOString(),
      configUsed: metadata.configUsed ?? 'default',
    },
  };
}

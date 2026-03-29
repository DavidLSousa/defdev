import { ComplianceViolation, ComplianceReport } from '../types/iac.js';
import { Severity } from '../types/severity.js';

const EMPTY_SEVERITY_COUNTS = (): Record<Severity, number> => ({
  [Severity.CRITICAL]: 0,
  [Severity.HIGH]: 0,
  [Severity.MEDIUM]: 0,
  [Severity.LOW]: 0,
  [Severity.INFO]: 0,
});

export function buildComplianceReport(
  violations: ComplianceViolation[],
  totalResources: number,
  executionTimeMs: number,
  frameworks: string[] = ['CIS'],
  agentVersion = '1.0.0'
): ComplianceReport {
  const bySeverity = EMPTY_SEVERITY_COUNTS();
  const byResourceType: Record<string, number> = {};

  for (const v of violations) {
    bySeverity[v.severity]++;
    byResourceType[v.resource.type] = (byResourceType[v.resource.type] ?? 0) + 1;
  }

  const violatedResourceNames = new Set(violations.map((v) => v.resource.name));
  const complianceScore =
    totalResources === 0
      ? 100
      : Math.round(((totalResources - violatedResourceNames.size) / totalResources) * 100);

  const recommendations = buildRecommendations(violations);

  return {
    summary: {
      totalResources,
      totalViolations: violations.length,
      complianceScore,
      bySeverity,
      byResourceType,
      executionTimeMs,
    },
    violations: violations.sort((a, b) => {
      const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as Record<string, number>;
      return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
    }),
    recommendations,
    metadata: {
      agentVersion,
      analyzedAt: new Date().toISOString(),
      frameworks,
    },
  };
}

function buildRecommendations(violations: ComplianceViolation[]): string[] {
  const seen = new Set<string>();
  const recs: string[] = [];
  for (const v of violations) {
    if (!seen.has(v.rule)) {
      seen.add(v.rule);
      recs.push(`[${v.severity.toUpperCase()}] ${v.remediation.description}`);
    }
  }
  return recs;
}

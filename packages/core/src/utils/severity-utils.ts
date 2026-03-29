import { Severity } from '../types/severity.js';
import { Finding } from '../types/finding.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.CRITICAL]: 4,
  [Severity.HIGH]: 3,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 1,
  [Severity.INFO]: 0,
};

export function severityToNumber(s: Severity): number {
  return SEVERITY_ORDER[s];
}

export function getHighestSeverity(findings: Finding[]): Severity {
  if (findings.length === 0) return Severity.INFO;
  return findings.reduce<Severity>(
    (highest, f) =>
      severityToNumber(f.severity) > severityToNumber(highest) ? f.severity : highest,
    Severity.INFO
  );
}

export function isAtLeastSeverity(actual: Severity, threshold: Severity): boolean {
  return severityToNumber(actual) >= severityToNumber(threshold);
}

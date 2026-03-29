import { describe, it, expect } from 'vitest';
import { severityToNumber, getHighestSeverity, isAtLeastSeverity } from '../utils/severity-utils.js';
import { Severity } from '../types/severity.js';
import { Finding, FindingCategory } from '../types/finding.js';

const f = (severity: Severity): Finding => ({
  id: '1', category: FindingCategory.INJECTION, severity,
  title: '', description: '', file: '', line: 0, column: 0,
  codeSnippet: '', recommendation: '', references: [],
});

describe('severityToNumber', () => {
  it('critical > high > medium > low > info', () => {
    expect(severityToNumber(Severity.CRITICAL)).toBeGreaterThan(severityToNumber(Severity.HIGH));
    expect(severityToNumber(Severity.HIGH)).toBeGreaterThan(severityToNumber(Severity.MEDIUM));
    expect(severityToNumber(Severity.MEDIUM)).toBeGreaterThan(severityToNumber(Severity.LOW));
    expect(severityToNumber(Severity.LOW)).toBeGreaterThan(severityToNumber(Severity.INFO));
  });
});

describe('getHighestSeverity', () => {
  it('returns INFO for empty array', () => {
    expect(getHighestSeverity([])).toBe(Severity.INFO);
  });

  it('returns the highest severity in the list', () => {
    const findings = [f(Severity.LOW), f(Severity.CRITICAL), f(Severity.MEDIUM)];
    expect(getHighestSeverity(findings)).toBe(Severity.CRITICAL);
  });
});

describe('isAtLeastSeverity', () => {
  it('returns true when actual meets threshold', () => {
    expect(isAtLeastSeverity(Severity.HIGH, Severity.HIGH)).toBe(true);
    expect(isAtLeastSeverity(Severity.CRITICAL, Severity.HIGH)).toBe(true);
  });

  it('returns false when actual is below threshold', () => {
    expect(isAtLeastSeverity(Severity.LOW, Severity.HIGH)).toBe(false);
  });
});

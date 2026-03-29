import { describe, it, expect } from 'vitest';
import { buildReport } from '../utils/report-builder.js';
import { Finding, FindingCategory } from '../types/finding.js';
import { Severity } from '../types/severity.js';

const makeFinding = (severity: Severity, category: FindingCategory): Finding => ({
  id: 'abc',
  category,
  severity,
  title: 'Test',
  description: 'Test finding',
  file: 'src/test.ts',
  line: 1,
  column: 1,
  codeSnippet: 'eval(userInput)',
  recommendation: 'Fix it',
  references: [],
});

describe('buildReport', () => {
  it('returns zero counts for empty findings', () => {
    const report = buildReport([], 5, 100);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.summary.totalFiles).toBe(5);
    expect(report.summary.bySeverity[Severity.CRITICAL]).toBe(0);
  });

  it('correctly counts findings by severity and category', () => {
    const findings: Finding[] = [
      makeFinding(Severity.CRITICAL, FindingCategory.INJECTION),
      makeFinding(Severity.HIGH, FindingCategory.INJECTION),
      makeFinding(Severity.CRITICAL, FindingCategory.SECRETS_EXPOSURE),
    ];
    const report = buildReport(findings, 3, 50);
    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.bySeverity[Severity.CRITICAL]).toBe(2);
    expect(report.summary.bySeverity[Severity.HIGH]).toBe(1);
    expect(report.summary.byCategory[FindingCategory.INJECTION]).toBe(2);
    expect(report.summary.byCategory[FindingCategory.SECRETS_EXPOSURE]).toBe(1);
  });

  it('sorts findings critical-first', () => {
    const findings: Finding[] = [
      makeFinding(Severity.LOW, FindingCategory.INJECTION),
      makeFinding(Severity.CRITICAL, FindingCategory.INJECTION),
      makeFinding(Severity.MEDIUM, FindingCategory.INJECTION),
    ];
    const report = buildReport(findings, 1, 10);
    expect(report.findings[0].severity).toBe(Severity.CRITICAL);
    expect(report.findings[2].severity).toBe(Severity.LOW);
  });
});

import * as core from '@actions/core';
import { AnalysisReport, ComplianceReport, Severity } from '@defdev/core';

export function reportDevSecOpsFindings(report: AnalysisReport): void {
  for (const finding of report.findings) {
    const annotationProps = {
      file: finding.file,
      startLine: finding.line,
      startColumn: finding.column,
      title: finding.title,
    };

    const message = `${finding.description}\n\nRecommendation: ${finding.recommendation}${finding.cwe ? `\nCWE: ${finding.cwe}` : ''}`;

    switch (finding.severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        core.error(message, annotationProps);
        break;
      case Severity.MEDIUM:
        core.warning(message, annotationProps);
        break;
      default:
        core.notice(message, annotationProps);
    }
  }
}

export function reportCspmViolations(report: ComplianceReport): void {
  for (const v of report.violations) {
    const message = `[${v.rule}] ${v.description}\n\nImpact: ${v.impact}\nRemediation: ${v.remediation.description}`;
    const annotationProps = {
      file: v.resource.file,
      startLine: v.resource.line,
      title: `${v.rule}: ${v.description}`,
    };

    switch (v.severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        core.error(message, annotationProps);
        break;
      case Severity.MEDIUM:
        core.warning(message, annotationProps);
        break;
      default:
        core.notice(message, annotationProps);
    }
  }
}

export async function buildJobSummary(
  devsecopsReport?: AnalysisReport,
  cspmReport?: ComplianceReport
): Promise<void> {
  await core.summary.addHeading('Security MVP Scan Results', 1);

  if (devsecopsReport) {
    const s = devsecopsReport.summary;
    await core.summary.addHeading('DevSecOps — Code Security', 2);
    await core.summary.addTable([
      [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
      ['Files Analyzed', String(s.totalFiles)],
      ['Total Findings', String(s.totalFindings)],
      ['Critical', String(s.bySeverity[Severity.CRITICAL])],
      ['High', String(s.bySeverity[Severity.HIGH])],
      ['Medium', String(s.bySeverity[Severity.MEDIUM])],
      ['Low', String(s.bySeverity[Severity.LOW])],
    ]);
  }

  if (cspmReport) {
    const s = cspmReport.summary;
    await core.summary.addHeading('CSPM — Cloud Security Posture', 2);
    await core.summary.addTable([
      [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
      ['Resources Scanned', String(s.totalResources)],
      ['Violations', String(s.totalViolations)],
      ['Compliance Score', `${s.complianceScore}%`],
      ['Critical', String(s.bySeverity[Severity.CRITICAL])],
      ['High', String(s.bySeverity[Severity.HIGH])],
    ]);
  }

  await core.summary.write();
}

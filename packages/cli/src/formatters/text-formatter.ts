import { AnalysisReport, Severity } from '@defdev/core';
import { ComplianceReport } from '@defdev/core';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const MAGENTA = '\x1b[35m';
const DIM = '\x1b[2m';

function severityColor(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL: return `\x1b[41m\x1b[97m CRITICAL \x1b[0m`;
    case Severity.HIGH:     return `${RED}${BOLD} HIGH ${RESET}`;
    case Severity.MEDIUM:   return `${YELLOW}${BOLD} MEDIUM ${RESET}`;
    case Severity.LOW:      return `${CYAN} LOW ${RESET}`;
    case Severity.INFO:     return `${DIM} INFO ${RESET}`;
  }
}

export function formatDevSecOpsReport(report: AnalysisReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}`);
  lines.push(`${BOLD}${MAGENTA}  DevSecOps Security Scan Report${RESET}`);
  lines.push(`${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}`);
  lines.push('');

  const { summary } = report;
  lines.push(`${BOLD}Summary${RESET}`);
  lines.push(`  Files analyzed : ${summary.totalFiles}`);
  lines.push(`  Total findings : ${summary.totalFindings}`);
  lines.push(`  Execution time : ${summary.executionTimeMs}ms`);
  lines.push('');
  lines.push(`  ${RED}Critical: ${summary.bySeverity[Severity.CRITICAL]}${RESET}  ` +
    `${RED}High: ${summary.bySeverity[Severity.HIGH]}${RESET}  ` +
    `${YELLOW}Medium: ${summary.bySeverity[Severity.MEDIUM]}${RESET}  ` +
    `${CYAN}Low: ${summary.bySeverity[Severity.LOW]}${RESET}`);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push(`${GREEN}${BOLD}✓ No security issues found!${RESET}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push(`${BOLD}Findings${RESET}`);
  lines.push('');

  for (const finding of report.findings) {
    lines.push(`${severityColor(finding.severity)} ${BOLD}${finding.title}${RESET}`);
    lines.push(`  ${DIM}${finding.file}:${finding.line}:${finding.column}${RESET}`);
    lines.push(`  ${finding.description}`);
    if (finding.codeSnippet) {
      lines.push(`  ${DIM}Code: ${finding.codeSnippet}${RESET}`);
    }
    lines.push(`  ${GREEN}Fix: ${finding.recommendation}${RESET}`);
    if (finding.cwe) lines.push(`  ${DIM}CWE: ${finding.cwe}${RESET}`);
    lines.push('');
  }

  return lines.join('\n');
}

export function formatCspmReport(report: ComplianceReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}`);
  lines.push(`${BOLD}${MAGENTA}  CSPM Cloud Security Posture Report${RESET}`);
  lines.push(`${BOLD}${MAGENTA}══════════════════════════════════════════${RESET}`);
  lines.push('');

  const { summary } = report;
  const scoreColor = summary.complianceScore >= 80 ? GREEN : summary.complianceScore >= 50 ? YELLOW : RED;
  lines.push(`${BOLD}Summary${RESET}`);
  lines.push(`  Resources scanned : ${summary.totalResources}`);
  lines.push(`  Violations found  : ${summary.totalViolations}`);
  lines.push(`  Compliance score  : ${scoreColor}${BOLD}${summary.complianceScore}%${RESET}`);
  lines.push(`  Execution time    : ${summary.executionTimeMs}ms`);
  lines.push('');
  lines.push(`  ${RED}Critical: ${summary.bySeverity[Severity.CRITICAL]}${RESET}  ` +
    `${RED}High: ${summary.bySeverity[Severity.HIGH]}${RESET}  ` +
    `${YELLOW}Medium: ${summary.bySeverity[Severity.MEDIUM]}${RESET}  ` +
    `${CYAN}Low: ${summary.bySeverity[Severity.LOW]}${RESET}`);
  lines.push('');

  if (report.violations.length === 0) {
    lines.push(`${GREEN}${BOLD}✓ No compliance violations found!${RESET}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push(`${BOLD}Violations${RESET}`);
  lines.push('');

  for (const v of report.violations) {
    lines.push(`${severityColor(v.severity)} ${BOLD}${v.rule}${RESET} — ${v.description}`);
    lines.push(`  Resource: ${v.resource.type}/${v.resource.name} @ ${v.resource.file}:${v.resource.line}`);
    lines.push(`  Impact: ${v.impact}`);
    lines.push(`  ${GREEN}Fix: ${v.remediation.description}${RESET}`);
    if (v.compliance.length > 0) {
      lines.push(`  ${DIM}Compliance: ${v.compliance.map((c) => `${c.framework} ${c.control}`).join(', ')}${RESET}`);
    }
    lines.push('');
  }

  if (report.recommendations.length > 0) {
    lines.push(`${BOLD}Top Recommendations${RESET}`);
    for (const rec of report.recommendations.slice(0, 5)) {
      lines.push(`  • ${rec}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

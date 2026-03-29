import { Finding, FindingCategory, Severity, generateFindingId } from '@defdev/core';

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | {
    source?: number;
    name?: string;
    dependency?: string;
    title?: string;
    url?: string;
    severity?: string;
    cwe?: string[];
    cvss?: { score: number };
    range?: string;
  }>;
  fixAvailable: boolean | { name: string; version: string };
}

interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: { vulnerabilities: Record<string, number> };
}

function mapSeverity(s: string): Severity {
  switch (s.toLowerCase()) {
    case 'critical': return Severity.CRITICAL;
    case 'high': return Severity.HIGH;
    case 'moderate':
    case 'medium': return Severity.MEDIUM;
    case 'low': return Severity.LOW;
    default: return Severity.INFO;
  }
}

export function parseNpmAudit(jsonOutput: string, packageJsonPath: string): Finding[] {
  let report: NpmAuditReport;
  try {
    report = JSON.parse(jsonOutput) as NpmAuditReport;
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  const vulns = report.vulnerabilities ?? {};

  for (const [pkgName, vuln] of Object.entries(vulns)) {
    const severity = mapSeverity(vuln.severity);
    const viaDetails = vuln.via.find((v) => typeof v === 'object') as {
      title?: string; url?: string; cwe?: string[]; cvss?: { score: number }
    } | undefined;

    const title = viaDetails?.title ?? `Vulnerable dependency: ${pkgName}`;
    const cwe = viaDetails?.cwe?.[0];
    const url = viaDetails?.url ?? '';

    findings.push({
      id: generateFindingId(packageJsonPath, 0, `SCA:${pkgName}`),
      category: FindingCategory.INSECURE_DEPENDENCIES,
      severity,
      title,
      description: `Package "${pkgName}" has a known vulnerability (${vuln.severity}).`,
      file: packageJsonPath,
      line: 0,
      column: 0,
      codeSnippet: `"${pkgName}"`,
      recommendation: vuln.fixAvailable
        ? `Run \`npm audit fix\` to upgrade "${pkgName}" to a patched version.`
        : `No automatic fix available. Review and manually update "${pkgName}".`,
      cwe,
      references: url ? [url] : [],
    });
  }

  return findings;
}

import { AnalysisReport, Severity } from '@defdev/core';

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number };
    };
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[] };
}

function severityToSarifLevel(s: Severity): string {
  switch (s) {
    case Severity.CRITICAL:
    case Severity.HIGH: return 'error';
    case Severity.MEDIUM: return 'warning';
    default: return 'note';
  }
}

export function formatSarif(report: AnalysisReport, toolName = 'security-mvp-devsecops'): string {
  const rulesMap = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of report.findings) {
    const ruleId = finding.cwe ?? finding.id;

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title.replace(/\s+/g, ''),
        shortDescription: { text: finding.description },
        helpUri: finding.references[0],
        properties: { tags: [finding.category] },
      });
    }

    results.push({
      ruleId,
      level: severityToSarifLevel(finding.severity),
      message: { text: `${finding.title}: ${finding.recommendation}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.file },
          region: { startLine: finding.line, startColumn: finding.column },
        },
      }],
    });
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: toolName,
          version: report.metadata.agentVersion,
          rules: Array.from(rulesMap.values()),
        },
      },
      results,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

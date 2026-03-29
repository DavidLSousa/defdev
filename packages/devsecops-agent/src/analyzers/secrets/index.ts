import { IAnalyzer, AnalysisInput, Finding, FindingCategory, generateFindingId } from '@defdev/core';
import { SECRET_PATTERNS } from './patterns.js';

export class SecretsAnalyzer implements IAnalyzer {
  async analyze(input: AnalysisInput): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const file of input.files) {
      findings.push(...this.scanFile(file.path, file.content));
    }

    return findings;
  }

  private scanFile(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      lines.forEach((lineContent, idx) => {
        const lineNum = idx + 1;

        // Skip comment lines
        const trimmed = lineContent.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

        const localRegex = new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '') + 'g');
        let match: RegExpExecArray | null;
        while ((match = localRegex.exec(lineContent)) !== null) {
          findings.push({
            id: generateFindingId(filePath, lineNum, pattern.name),
            category: FindingCategory.SECRETS_EXPOSURE,
            severity: pattern.severity,
            title: pattern.name,
            description: pattern.description,
            file: filePath,
            line: lineNum,
            column: match.index + 1,
            codeSnippet: this.redactLine(lineContent.trim(), match[0]),
            recommendation: pattern.recommendation,
            cwe: pattern.cwe,
            references: [],
          });
        }
      });
    }

    return findings;
  }

  private redactLine(line: string, secret: string): string {
    if (secret.length <= 8) return line;
    const visible = secret.slice(0, 4);
    const redacted = '*'.repeat(Math.min(secret.length - 4, 20));
    return line.replace(secret, `${visible}${redacted}`);
  }
}

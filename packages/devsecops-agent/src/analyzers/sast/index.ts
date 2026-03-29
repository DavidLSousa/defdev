import { IAnalyzer, AnalysisInput, Finding } from '@defdev/core';
import { detectInjection } from './rules/injection-rules.js';
import { detectAuthIssues } from './rules/auth-rules.js';
import { detectCryptoIssues } from './rules/crypto-rules.js';

export class SastAnalyzer implements IAnalyzer {
  async analyze(input: AnalysisInput): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    for (const file of input.files) {
      const results = await Promise.all([
        Promise.resolve(detectInjection(file)),
        Promise.resolve(detectAuthIssues(file)),
        Promise.resolve(detectCryptoIssues(file)),
      ]);
      allFindings.push(...results.flat());
    }

    return allFindings;
  }
}

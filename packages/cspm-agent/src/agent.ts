import { readProjectFiles, buildComplianceReport, ComplianceReport } from '@defdev/core';
import { CspmConfig, defaultConfig } from './config.js';
import { getParser } from './parsers/index.js';
import { runAllRules } from './rules/index.js';

// Register all rules by importing the rule modules
import './rules/s3-rules.js';
import './rules/security-group-rules.js';
import './rules/iam-rules.js';

export class CspmAgent {
  private readonly config: CspmConfig;

  constructor(config: Partial<CspmConfig> & { rootDir: string }) {
    this.config = { ...defaultConfig, ...config };
  }

  async run(): Promise<ComplianceReport> {
    const start = Date.now();

    const files = await readProjectFiles(
      this.config.rootDir,
      this.config.includePatterns,
      this.config.excludePatterns
    );

    const allResources = [];
    for (const file of files) {
      const parser = getParser(file.path);
      if (!parser) continue;
      try {
        const resources = await parser.parse(file.content, file.path);
        allResources.push(...resources);
      } catch (err) {
        console.warn(`[CSPM] Failed to parse ${file.path}:`, (err as Error).message);
      }
    }

    const violations = runAllRules(allResources);

    return buildComplianceReport(
      violations,
      allResources.length,
      Date.now() - start,
      this.config.complianceFrameworks
    );
  }

  async analyzeContent(content: string, fileType: 'terraform' | 'cloudformation'): Promise<ComplianceReport> {
    const start = Date.now();
    const fakeFilePath = fileType === 'terraform' ? 'snippet.tf' : 'snippet.yaml';

    const parser = getParser(fakeFilePath);
    if (!parser) return buildComplianceReport([], 0, 0);

    const resources = await parser.parse(content, fakeFilePath);
    const violations = runAllRules(resources);

    return buildComplianceReport(violations, resources.length, Date.now() - start);
  }
}

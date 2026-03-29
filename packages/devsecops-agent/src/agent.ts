import { readProjectFiles, buildReport, AnalysisReport, Finding } from '@defdev/core';
import { DevSecOpsConfig, defaultConfig } from './config.js';
import { SastAnalyzer } from './analyzers/sast/index.js';
import { SecretsAnalyzer } from './analyzers/secrets/index.js';
import { ScaAnalyzer } from './analyzers/sca/index.js';

export class DevSecOpsAgent {
  private readonly config: DevSecOpsConfig;

  constructor(config: Partial<DevSecOpsConfig> & { rootDir: string }) {
    this.config = { ...defaultConfig, ...config };
  }

  async run(): Promise<AnalysisReport> {
    const start = Date.now();

    const files = await readProjectFiles(
      this.config.rootDir,
      this.config.includePatterns,
      this.config.excludePatterns
    );

    const input = { files, rootDir: this.config.rootDir };

    type Analyzer = { analyze(i: typeof input): Promise<Finding[]> };
    const analyzers: Analyzer[] = [
      this.config.enableSast ? new SastAnalyzer() : null,
      this.config.enableSecrets ? new SecretsAnalyzer() : null,
      this.config.enableSca ? new ScaAnalyzer() : null,
    ].filter((a): a is Analyzer => a !== null);

    const results = await Promise.all(analyzers.map((a) => a.analyze(input)));
    const allFindings = results.flat();

    return buildReport(allFindings, files.length, Date.now() - start);
  }

  async analyzeCode(code: string, filename = 'snippet.ts'): Promise<AnalysisReport> {
    const start = Date.now();
    const input = { files: [{ path: filename, content: code }], rootDir: '.' };

    const findings: Finding[] = [];
    if (this.config.enableSast) {
      findings.push(...await new SastAnalyzer().analyze(input));
    }
    if (this.config.enableSecrets) {
      findings.push(...await new SecretsAnalyzer().analyze(input));
    }

    return buildReport(findings, 1, Date.now() - start);
  }
}

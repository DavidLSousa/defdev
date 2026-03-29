import { exec } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { join } from 'path';
import { IAnalyzer, AnalysisInput, Finding } from '@defdev/core';
import { parseNpmAudit } from './npm-audit-parser.js';

const execAsync = promisify(exec);

export class ScaAnalyzer implements IAnalyzer {
  async analyze(input: AnalysisInput): Promise<Finding[]> {
    const packageJsonPath = join(input.rootDir, 'package.json');
    const lockPath = join(input.rootDir, 'package-lock.json');

    if (!existsSync(packageJsonPath)) return [];

    try {
      return await this.runNpmAudit(input.rootDir, packageJsonPath);
    } catch (err) {
      if (!existsSync(lockPath)) {
        console.warn('[SCA] Skipping npm audit: package-lock.json not found.');
      } else {
        console.warn('[SCA] npm audit failed:', (err as Error).message);
      }
      return [];
    }
  }

  private async runNpmAudit(cwd: string, packageJsonPath: string): Promise<Finding[]> {
    try {
      const { stdout } = await execAsync('npm audit --json', { cwd });
      return parseNpmAudit(stdout, packageJsonPath);
    } catch (err: unknown) {
      // npm audit exits with code 1 when vulnerabilities are found — that's still valid JSON output
      const execError = err as { stdout?: string; code?: number };
      if (execError.stdout) {
        return parseNpmAudit(execError.stdout, packageJsonPath);
      }
      throw err;
    }
  }
}

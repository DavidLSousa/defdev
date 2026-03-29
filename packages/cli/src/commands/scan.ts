import { Command } from 'commander';
import { writeFileSync } from 'fs';
import { resolve } from 'path';
import { DevSecOpsAgent } from '@defdev/devsecops-agent';
import { Severity } from '@defdev/core';
import { formatDevSecOpsReport, formatSarif } from '../formatters/index.js';
import { isAtLeastSeverity } from '@defdev/core';

export function buildScanCommand(): Command {
  return new Command('scan')
    .description('Scan TypeScript/JavaScript code for security vulnerabilities')
    .argument('[path]', 'Directory to scan', '.')
    .option('-f, --format <type>', 'Output format: text, json, sarif', 'text')
    .option('-o, --output <file>', 'Write report to file instead of stdout')
    .option('-s, --severity <level>', 'Minimum severity to report: critical, high, medium, low, info', 'info')
    .option('--no-sast', 'Disable SAST analysis')
    .option('--no-secrets', 'Disable secrets detection')
    .option('--no-sca', 'Disable dependency vulnerability analysis')
    .option('--fail-on <level>', 'Exit with code 1 if findings at or above this severity exist')
    .action(async (path: string, options: {
      format: string;
      output?: string;
      severity: string;
      sast: boolean;
      secrets: boolean;
      sca: boolean;
      failOn?: string;
    }) => {
      const rootDir = resolve(path);
      console.error(`\n[DevSecOps] Scanning: ${rootDir}\n`);

      const agent = new DevSecOpsAgent({
        rootDir,
        enableSast: options.sast,
        enableSecrets: options.secrets,
        enableSca: options.sca,
      });

      const report = await agent.run();

      let output: string;
      switch (options.format) {
        case 'json':
          output = JSON.stringify(report, null, 2);
          break;
        case 'sarif':
          output = formatSarif(report);
          break;
        default:
          output = formatDevSecOpsReport(report);
      }

      if (options.output) {
        writeFileSync(options.output, output, 'utf-8');
        console.error(`[DevSecOps] Report written to: ${options.output}`);
      } else {
        process.stdout.write(output + '\n');
      }

      // Exit code logic
      if (options.failOn) {
        const threshold = options.failOn as Severity;
        const hasViolations = report.findings.some((f) =>
          isAtLeastSeverity(f.severity, threshold)
        );
        if (hasViolations) process.exit(1);
      }
    });
}

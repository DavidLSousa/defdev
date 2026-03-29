import { Command } from 'commander';
import { writeFileSync } from 'fs';
import { resolve } from 'path';
import { CspmAgent } from '@defdev/cspm-agent';
import { Severity } from '@defdev/core';
import { formatCspmReport } from '../formatters/index.js';
import { isAtLeastSeverity } from '@defdev/core';

export function buildCspmCommand(): Command {
  return new Command('cspm')
    .description('Scan Terraform/CloudFormation files for cloud misconfigurations')
    .argument('[path]', 'Directory to scan', '.')
    .option('-f, --format <type>', 'Output format: text, json', 'text')
    .option('-o, --output <file>', 'Write report to file instead of stdout')
    .option('--framework <name>', 'Compliance framework: CIS, PCI-DSS', 'CIS')
    .option('--fail-on <level>', 'Exit with code 1 if violations at or above this severity exist')
    .action(async (path: string, options: {
      format: string;
      output?: string;
      framework: string;
      failOn?: string;
    }) => {
      const rootDir = resolve(path);
      console.error(`\n[CSPM] Scanning: ${rootDir}\n`);

      const agent = new CspmAgent({
        rootDir,
        complianceFrameworks: [options.framework as 'CIS' | 'PCI-DSS' | 'HIPAA'],
      });

      const report = await agent.run();

      let output: string;
      switch (options.format) {
        case 'json':
          output = JSON.stringify(report, null, 2);
          break;
        default:
          output = formatCspmReport(report);
      }

      if (options.output) {
        writeFileSync(options.output, output, 'utf-8');
        console.error(`[CSPM] Report written to: ${options.output}`);
      } else {
        process.stdout.write(output + '\n');
      }

      if (options.failOn) {
        const threshold = options.failOn as Severity;
        const hasViolations = report.violations.some((v) =>
          isAtLeastSeverity(v.severity, threshold)
        );
        if (hasViolations) process.exit(1);
      }
    });
}

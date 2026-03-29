import { Command } from 'commander';
import { buildScanCommand } from './commands/scan.js';
import { buildCspmCommand } from './commands/cspm.js';

const program = new Command();

program
  .name('security-mvp')
  .description('Security scanning agents for TypeScript code and cloud infrastructure')
  .version('1.0.0');

program.addCommand(buildScanCommand());
program.addCommand(buildCspmCommand());

export { program };

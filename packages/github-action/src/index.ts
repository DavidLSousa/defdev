import * as core from '@actions/core';
import { resolve } from 'path';
import { DevSecOpsAgent } from '@defdev/devsecops-agent';
import { CspmAgent } from '@defdev/cspm-agent';
import { AnalysisReport, ComplianceReport, Severity, isAtLeastSeverity } from '@defdev/core';
import { reportDevSecOpsFindings, reportCspmViolations, buildJobSummary } from './github-reporter.js';

async function run(): Promise<void> {
  try {
    const scanType = core.getInput('scan-type') || 'both';
    const path = core.getInput('path') || '.';
    const failOnSeverity = (core.getInput('fail-on-severity') || 'high') as Severity;
    const rootDir = resolve(path);

    let devsecopsReport: AnalysisReport | undefined;
    let cspmReport: ComplianceReport | undefined;

    if (scanType === 'devsecops' || scanType === 'both') {
      core.info(`[DevSecOps] Scanning: ${rootDir}`);
      const agent = new DevSecOpsAgent({ rootDir });
      devsecopsReport = await agent.run();
      core.info(`[DevSecOps] Found ${devsecopsReport.summary.totalFindings} findings`);
      reportDevSecOpsFindings(devsecopsReport);
      core.setOutput('total-findings', String(devsecopsReport.summary.totalFindings));
    }

    if (scanType === 'cspm' || scanType === 'both') {
      core.info(`[CSPM] Scanning: ${rootDir}`);
      const agent = new CspmAgent({ rootDir });
      cspmReport = await agent.run();
      core.info(`[CSPM] Found ${cspmReport.summary.totalViolations} violations, score: ${cspmReport.summary.complianceScore}%`);
      reportCspmViolations(cspmReport);
      core.setOutput('compliance-score', String(cspmReport.summary.complianceScore));
    }

    await buildJobSummary(devsecopsReport, cspmReport);

    // Determine if we should fail
    const hasCritical =
      (devsecopsReport?.summary.bySeverity[Severity.CRITICAL] ?? 0) > 0 ||
      (cspmReport?.summary.bySeverity[Severity.CRITICAL] ?? 0) > 0;
    core.setOutput('has-critical', String(hasCritical));

    const shouldFail =
      (devsecopsReport?.findings.some((f) => isAtLeastSeverity(f.severity, failOnSeverity)) ?? false) ||
      (cspmReport?.violations.some((v) => isAtLeastSeverity(v.severity, failOnSeverity)) ?? false);

    if (shouldFail) {
      core.setFailed(`Security scan found issues at or above ${failOnSeverity} severity.`);
    }
  } catch (error) {
    core.setFailed((error as Error).message);
  }
}

run();

import { IaCResource, ComplianceViolation, Severity, generateFindingId } from '@defdev/core';

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  resourceTypes: string[];
  frameworks: Record<string, string>;
  check(resource: IaCResource): ComplianceViolation | null;
}

const registry: ComplianceRule[] = [];

export function registerRule(rule: ComplianceRule): void {
  registry.push(rule);
}

export function runAllRules(resources: IaCResource[]): ComplianceViolation[] {
  const violations: ComplianceViolation[] = [];

  for (const resource of resources) {
    for (const rule of registry) {
      if (rule.resourceTypes.some((t) => resource.type === t || resource.type.startsWith(t))) {
        const violation = rule.check(resource);
        if (violation) violations.push(violation);
      }
    }
  }

  return violations;
}

export function makeViolation(
  rule: ComplianceRule,
  resource: IaCResource,
  description: string,
  impact: string,
  remediation: string,
  remediationCode?: string
): ComplianceViolation {
  return {
    id: generateFindingId(resource.file, resource.lineStart, rule.id),
    rule: rule.id,
    severity: rule.severity,
    resource: {
      type: resource.type,
      name: resource.name,
      file: resource.file,
      line: resource.lineStart,
    },
    description,
    impact,
    remediation: {
      description: remediation,
      code: remediationCode,
      references: Object.values(rule.frameworks).map((ctrl) =>
        `https://www.cisecurity.org/benchmark/amazon_web_services (Control ${ctrl})`
      ),
    },
    compliance: Object.entries(rule.frameworks).map(([framework, control]) => ({
      framework: framework as 'CIS' | 'PCI-DSS' | 'HIPAA' | 'NIST',
      control,
      description: rule.description,
    })),
  };
}

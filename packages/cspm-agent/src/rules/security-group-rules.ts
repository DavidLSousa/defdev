import { IaCResource, Severity } from '@defdev/core';
import { registerRule, makeViolation, ComplianceRule } from './index.js';

type IngressRule = {
  from_port?: number;
  to_port?: number;
  protocol?: string;
  cidr_blocks?: string[];
  ipv6_cidr_blocks?: string[];
};

function hasOpenCidr(rule: IngressRule): boolean {
  return (
    (rule.cidr_blocks?.includes('0.0.0.0/0') ?? false) ||
    (rule.ipv6_cidr_blocks?.includes('::/0') ?? false)
  );
}

function getIngressRules(resource: IaCResource): IngressRule[] {
  const ingress = resource.properties['ingress'];
  if (Array.isArray(ingress)) return ingress as IngressRule[];
  if (ingress && typeof ingress === 'object') return [ingress as IngressRule];
  return [];
}

const sgSshOpen: ComplianceRule = {
  id: 'SG-001',
  name: 'Security Group SSH Open to World',
  description: 'Security group should not allow SSH (port 22) from 0.0.0.0/0.',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_security_group'],
  frameworks: { CIS: '4.1' },
  check(resource) {
    const ingressRules = getIngressRules(resource);
    const vulnerable = ingressRules.some(
      (r) => (r.from_port ?? 0) <= 22 && (r.to_port ?? 0) >= 22 && hasOpenCidr(r)
    );
    if (vulnerable) {
      return makeViolation(
        this, resource,
        `Security group "${resource.name}" allows SSH (port 22) from 0.0.0.0/0.`,
        'Any machine on the internet can attempt to connect via SSH.',
        'Restrict SSH access to specific trusted IP ranges or use AWS Systems Manager Session Manager.',
        `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["YOUR_TRUSTED_IP/32"]\n}`
      );
    }
    return null;
  },
};

const sgRdpOpen: ComplianceRule = {
  id: 'SG-002',
  name: 'Security Group RDP Open to World',
  description: 'Security group should not allow RDP (port 3389) from 0.0.0.0/0.',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_security_group'],
  frameworks: { CIS: '4.2' },
  check(resource) {
    const ingressRules = getIngressRules(resource);
    const vulnerable = ingressRules.some(
      (r) => (r.from_port ?? 0) <= 3389 && (r.to_port ?? 0) >= 3389 && hasOpenCidr(r)
    );
    if (vulnerable) {
      return makeViolation(
        this, resource,
        `Security group "${resource.name}" allows RDP (port 3389) from 0.0.0.0/0.`,
        'Any machine on the internet can attempt to connect via RDP.',
        'Restrict RDP access to specific trusted IP ranges.',
        `ingress {\n  from_port   = 3389\n  to_port     = 3389\n  protocol    = "tcp"\n  cidr_blocks = ["YOUR_TRUSTED_IP/32"]\n}`
      );
    }
    return null;
  },
};

const sgAllTrafficOpen: ComplianceRule = {
  id: 'SG-003',
  name: 'Security Group All Traffic Open to World',
  description: 'Security group should not allow all traffic (-1) from 0.0.0.0/0.',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_security_group'],
  frameworks: { CIS: '4.3' },
  check(resource) {
    const ingressRules = getIngressRules(resource);
    const vulnerable = ingressRules.some(
      (r) => (r.protocol === '-1' || r.protocol === 'all') && hasOpenCidr(r)
    );
    if (vulnerable) {
      return makeViolation(
        this, resource,
        `Security group "${resource.name}" allows all traffic from 0.0.0.0/0.`,
        'All ports and protocols are open to the internet.',
        'Remove the all-traffic ingress rule and define specific rules for required ports only.',
      );
    }
    return null;
  },
};

registerRule(sgSshOpen);
registerRule(sgRdpOpen);
registerRule(sgAllTrafficOpen);

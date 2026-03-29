import { Severity } from '@defdev/core';
import { registerRule, makeViolation, ComplianceRule } from './index.js';

type PolicyStatement = {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
  Principal?: unknown;
};

type PolicyDocument = {
  Statement?: PolicyStatement[];
};

function getPolicyStatements(resource: { properties: Record<string, unknown> }): PolicyStatement[] {
  const policyDoc = resource.properties['policy'] ?? resource.properties['assume_role_policy'];
  if (!policyDoc) return [];
  try {
    const doc: PolicyDocument = typeof policyDoc === 'string'
      ? JSON.parse(policyDoc) as PolicyDocument
      : policyDoc as PolicyDocument;
    return doc.Statement ?? [];
  } catch {
    return [];
  }
}

function isWildcardPolicy(statements: PolicyStatement[]): boolean {
  return statements.some((s) => {
    const actions = Array.isArray(s.Action) ? s.Action : [s.Action ?? ''];
    const resources = Array.isArray(s.Resource) ? s.Resource : [s.Resource ?? ''];
    return (
      s.Effect === 'Allow' &&
      actions.includes('*') &&
      resources.includes('*')
    );
  });
}

const iamWildcardPolicy: ComplianceRule = {
  id: 'IAM-001',
  name: 'IAM Policy With Wildcard Actions',
  description: 'IAM policy should not allow all actions (*) on all resources (*).',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy'],
  frameworks: { CIS: '1.22' },
  check(resource) {
    const statements = getPolicyStatements(resource);
    if (isWildcardPolicy(statements)) {
      return makeViolation(
        this, resource,
        `IAM policy "${resource.name}" grants Action: "*" on Resource: "*".`,
        'Grants full administrative access. A compromised identity has unrestricted AWS access.',
        'Apply the principle of least privilege: specify only the required actions and resources.',
        `{\n  "Effect": "Allow",\n  "Action": [\n    "s3:GetObject",\n    "s3:PutObject"\n  ],\n  "Resource": "arn:aws:s3:::my-bucket/*"\n}`
      );
    }
    return null;
  },
};

const iamAdminAccess: ComplianceRule = {
  id: 'IAM-002',
  name: 'IAM Entity With AdministratorAccess Policy',
  description: 'IAM users, groups, or roles should not have AdministratorAccess managed policy attached.',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_iam_role_policy_attachment', 'aws_iam_user_policy_attachment', 'aws_iam_group_policy_attachment'],
  frameworks: { CIS: '1.22' },
  check(resource) {
    const policyArn = resource.properties['policy_arn'] as string | undefined;
    if (policyArn?.includes('AdministratorAccess')) {
      return makeViolation(
        this, resource,
        `"${resource.name}" attaches the AdministratorAccess policy.`,
        'Full administrative access granted. Violates the principle of least privilege.',
        'Replace AdministratorAccess with a least-privilege custom policy.',
      );
    }
    return null;
  },
};

const iamInlinePolicy: ComplianceRule = {
  id: 'IAM-003',
  name: 'Inline IAM Policy',
  description: 'Inline policies are harder to audit. Use managed policies instead.',
  severity: Severity.LOW,
  resourceTypes: ['aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy'],
  frameworks: { CIS: '1.21' },
  check(resource) {
    return makeViolation(
      this, resource,
      `"${resource.name}" is an inline IAM policy.`,
      'Inline policies cannot be reused or audited centrally, increasing management overhead.',
      'Convert to a managed policy (aws_iam_policy) and use policy attachments.',
    );
  },
};

const iamPasswordPolicy: ComplianceRule = {
  id: 'IAM-004',
  name: 'IAM Password Policy Too Weak',
  description: 'IAM account password policy should require minimum length of 14 characters.',
  severity: Severity.MEDIUM,
  resourceTypes: ['aws_iam_account_password_policy'],
  frameworks: { CIS: '1.8' },
  check(resource) {
    const minLength = resource.properties['minimum_password_length'] as number | undefined;
    if (!minLength || minLength < 14) {
      return makeViolation(
        this, resource,
        `IAM account password policy requires only ${minLength ?? 0} characters (minimum should be 14).`,
        'Weak password policies increase risk of brute-force account compromise.',
        'Set minimum_password_length to at least 14.',
        `resource "aws_iam_account_password_policy" "strict" {\n  minimum_password_length = 14\n  require_uppercase_characters = true\n  require_lowercase_characters = true\n  require_numbers = true\n  require_symbols = true\n}`
      );
    }
    return null;
  },
};

registerRule(iamWildcardPolicy);
registerRule(iamAdminAccess);
registerRule(iamInlinePolicy);
registerRule(iamPasswordPolicy);

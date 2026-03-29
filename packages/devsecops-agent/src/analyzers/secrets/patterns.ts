import { Severity } from '@defdev/core';

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  cwe: string;
  description: string;
  recommendation: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: Severity.CRITICAL,
    cwe: 'CWE-798',
    description: 'AWS Access Key ID found in source code.',
    recommendation: 'Remove the key immediately, rotate it in AWS IAM, and use environment variables or AWS IAM roles.',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"`]?([A-Za-z0-9/+]{40})['"`]?/gi,
    severity: Severity.CRITICAL,
    cwe: 'CWE-798',
    description: 'AWS Secret Access Key found in source code.',
    recommendation: 'Remove immediately, rotate credentials, and use AWS Secrets Manager or environment variables.',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[a-zA-Z0-9]{36,40}/g,
    severity: Severity.CRITICAL,
    cwe: 'CWE-798',
    description: 'GitHub Personal Access Token found in source code.',
    recommendation: 'Revoke the token immediately at github.com/settings/tokens and use environment variables.',
  },
  {
    name: 'GitHub OAuth Token',
    regex: /gho_[a-zA-Z0-9]{36,40}/g,
    severity: Severity.CRITICAL,
    cwe: 'CWE-798',
    description: 'GitHub OAuth Token found in source code.',
    recommendation: 'Revoke immediately and use environment variables.',
  },
  {
    name: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: Severity.CRITICAL,
    cwe: 'CWE-321',
    description: 'Private key found in source code.',
    recommendation: 'Remove the private key, rotate it, and store it securely (secrets manager, environment variable).',
  },
  {
    name: 'Generic API Key',
    regex: /(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]/gi,
    severity: Severity.HIGH,
    cwe: 'CWE-798',
    description: 'Possible API key hardcoded in source code.',
    recommendation: 'Move the API key to an environment variable and load it at runtime.',
  },
  {
    name: 'Database Connection String',
    regex: /(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^:]+:[^@\s]+@[^\s'"`,)]+/gi,
    severity: Severity.CRITICAL,
    cwe: 'CWE-312',
    description: 'Database connection string with credentials found in source code.',
    recommendation: 'Move the connection string to an environment variable. Never commit credentials.',
  },
  {
    name: 'JWT Token',
    regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    severity: Severity.HIGH,
    cwe: 'CWE-522',
    description: 'A JWT token is hardcoded in source code.',
    recommendation: 'Remove the token. Tokens are user-specific and must not be committed.',
  },
  {
    name: 'Hardcoded Password',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi,
    severity: Severity.HIGH,
    cwe: 'CWE-259',
    description: 'Hardcoded password found in source code.',
    recommendation: 'Use environment variables or a secrets manager to supply passwords at runtime.',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    severity: Severity.HIGH,
    cwe: 'CWE-798',
    description: 'Slack Webhook URL found in source code.',
    recommendation: 'Revoke the webhook and store it in an environment variable.',
  },
];

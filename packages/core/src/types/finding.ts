import { Severity } from './severity.js';

export enum FindingCategory {
  INJECTION = 'injection',
  SECRETS_EXPOSURE = 'secrets_exposure',
  INSECURE_DEPENDENCIES = 'insecure_dependencies',
  AUTH_ISSUES = 'auth_issues',
  CRYPTO_ISSUES = 'crypto_issues',
  MISCONFIGURATION = 'misconfiguration',
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  codeSnippet: string;
  recommendation: string;
  cwe?: string;
  cve?: string;
  references: string[];
}

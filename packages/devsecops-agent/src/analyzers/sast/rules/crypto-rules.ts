import { Finding, FindingCategory, Severity, generateFindingId } from '@defdev/core';
import { FileEntry } from '@defdev/core';

interface CryptoRule {
  regex: RegExp;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  recommendation: string;
  references: string[];
}

const CRYPTO_RULES: CryptoRule[] = [
  {
    regex: /Math\.random\s*\(\s*\)/g,
    title: 'Insecure Random Number Generation',
    description: 'Math.random() is not cryptographically secure and must not be used for security tokens or passwords.',
    severity: Severity.HIGH,
    cwe: 'CWE-338',
    recommendation: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.',
    references: ['https://cwe.mitre.org/data/definitions/338.html'],
  },
  {
    regex: /createCipher\s*\(\s*['"`]des['"`]/gi,
    title: 'Use of DES Encryption',
    description: 'DES is an obsolete cipher broken by brute-force attacks.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-326',
    recommendation: 'Use AES-256-GCM for symmetric encryption.',
    references: ['https://cwe.mitre.org/data/definitions/326.html'],
  },
  {
    regex: /createCipher\s*\(\s*['"`]rc4['"`]/gi,
    title: 'Use of RC4 Encryption',
    description: 'RC4 is a broken cipher with known plaintext attacks.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-326',
    recommendation: 'Use AES-256-GCM for symmetric encryption.',
    references: ['https://cwe.mitre.org/data/definitions/326.html'],
  },
  {
    regex: /createCipheriv\s*\(\s*['"`]aes[^'"`]*['"`]\s*,[^,]+,\s*['"`][0-9a-fA-F]{32}['"`]/g,
    title: 'Hardcoded Encryption Key',
    description: 'Encryption key is hardcoded in source code. Keys must be stored in secure vaults or environment variables.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-321',
    recommendation: 'Load encryption keys from environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
    references: ['https://cwe.mitre.org/data/definitions/321.html'],
  },
  {
    regex: /pbkdf2(?:Sync)?\s*\([^,]+,\s*[^,]+,\s*(?:[1-9]\d{0,2}|[1-3]\d{3})\s*,/g,
    title: 'PBKDF2 With Too Few Iterations',
    description: 'PBKDF2 iteration count is below the OWASP minimum of 600,000.',
    severity: Severity.MEDIUM,
    cwe: 'CWE-916',
    recommendation: 'Use at least 600,000 iterations with PBKDF2-SHA256, or prefer argon2id.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  },
];

export function detectCryptoIssues(file: FileEntry): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split('\n');

  for (const rule of CRYPTO_RULES) {
    lines.forEach((lineContent, idx) => {
      const lineNum = idx + 1;
      const localRegex = new RegExp(rule.regex.source, rule.regex.flags.replace('g', '') + 'g');
      let match: RegExpExecArray | null;
      while ((match = localRegex.exec(lineContent)) !== null) {
        findings.push({
          id: generateFindingId(file.path, lineNum, rule.cwe),
          category: FindingCategory.CRYPTO_ISSUES,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          file: file.path,
          line: lineNum,
          column: match.index + 1,
          codeSnippet: lineContent.trim(),
          recommendation: rule.recommendation,
          cwe: rule.cwe,
          references: rule.references,
        });
      }
    });
  }

  return findings;
}

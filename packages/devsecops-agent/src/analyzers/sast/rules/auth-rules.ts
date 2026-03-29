import { Finding, FindingCategory, Severity, generateFindingId } from '@defdev/core';
import { FileEntry } from '@defdev/core';

interface AuthRule {
  regex: RegExp;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  recommendation: string;
  references: string[];
}

const AUTH_RULES: AuthRule[] = [
  {
    regex: /jwt\.decode\s*\(/g,
    title: 'JWT Decoded Without Verification',
    description: 'jwt.decode() does not verify the signature. An attacker can forge tokens.',
    severity: Severity.HIGH,
    cwe: 'CWE-347',
    recommendation: 'Use jwt.verify() instead of jwt.decode() to validate the token signature.',
    references: ['https://cwe.mitre.org/data/definitions/347.html'],
  },
  {
    regex: /jwt\.sign\s*\([^,]+,\s*['"`][^'"`]{0,40}['"`]/g,
    title: 'Hardcoded JWT Secret',
    description: 'JWT signed with a hardcoded string secret. Secrets must come from environment variables.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-798',
    recommendation: 'Load the JWT secret from an environment variable: process.env.JWT_SECRET',
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
  },
  {
    regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]/g,
    title: 'CORS Wildcard Origin',
    description: 'CORS configured with origin: "*" allows any domain to make cross-origin requests.',
    severity: Severity.HIGH,
    cwe: 'CWE-942',
    recommendation: 'Restrict CORS origin to specific trusted domains.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  {
    regex: /cors\s*\(\s*\)/g,
    title: 'CORS Without Configuration',
    description: 'cors() called without options defaults to allowing all origins.',
    severity: Severity.MEDIUM,
    cwe: 'CWE-942',
    recommendation: 'Configure CORS with an explicit origin allowlist.',
    references: ['https://cwe.mitre.org/data/definitions/942.html'],
  },
  {
    regex: /dangerouslySetInnerHTML\s*=/g,
    title: 'dangerouslySetInnerHTML Usage',
    description: 'React dangerouslySetInnerHTML can cause XSS if content is not sanitized.',
    severity: Severity.HIGH,
    cwe: 'CWE-79',
    recommendation: 'Sanitize HTML using DOMPurify before passing to dangerouslySetInnerHTML.',
    references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'],
  },
  {
    regex: /createHash\s*\(\s*['"`]md5['"`]\s*\)/gi,
    title: 'Use of MD5 Hashing Algorithm',
    description: 'MD5 is cryptographically broken and should not be used for security purposes.',
    severity: Severity.HIGH,
    cwe: 'CWE-328',
    recommendation: 'Use SHA-256 or stronger for hashing. For passwords, use bcrypt, argon2, or scrypt.',
    references: ['https://cwe.mitre.org/data/definitions/328.html'],
  },
  {
    regex: /createHash\s*\(\s*['"`]sha1['"`]\s*\)/gi,
    title: 'Use of SHA-1 Hashing Algorithm',
    description: 'SHA-1 is deprecated and vulnerable to collision attacks.',
    severity: Severity.MEDIUM,
    cwe: 'CWE-328',
    recommendation: 'Use SHA-256 or stronger for hashing.',
    references: ['https://cwe.mitre.org/data/definitions/328.html'],
  },
];

export function detectAuthIssues(file: FileEntry): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split('\n');

  for (const rule of AUTH_RULES) {
    lines.forEach((lineContent, idx) => {
      const lineNum = idx + 1;
      const localRegex = new RegExp(rule.regex.source, rule.regex.flags.replace('g', '') + 'g');
      let match: RegExpExecArray | null;
      while ((match = localRegex.exec(lineContent)) !== null) {
        findings.push({
          id: generateFindingId(file.path, lineNum, rule.cwe),
          category: FindingCategory.AUTH_ISSUES,
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

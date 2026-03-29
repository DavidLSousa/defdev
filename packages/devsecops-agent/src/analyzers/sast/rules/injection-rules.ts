import { Finding, FindingCategory } from '@defdev/core';
import { Severity } from '@defdev/core';
import { generateFindingId } from '@defdev/core';
import { FileEntry } from '@defdev/core';

interface RuleMatch {
  regex: RegExp;
  title: string;
  description: string;
  severity: Severity;
  cwe: string;
  recommendation: string;
  references: string[];
}

const INJECTION_RULES: RuleMatch[] = [
  {
    regex: /\beval\s*\(/g,
    title: 'Use of eval()',
    description: 'eval() executes arbitrary code and is a critical injection vector.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-95',
    recommendation: 'Remove eval(). Use safer alternatives like JSON.parse() for data or explicit function calls.',
    references: ['https://owasp.org/www-community/attacks/Code_Injection'],
  },
  {
    regex: /new\s+Function\s*\(/g,
    title: 'Dynamic Function Construction',
    description: 'new Function() creates functions from strings and is equivalent to eval().',
    severity: Severity.CRITICAL,
    cwe: 'CWE-95',
    recommendation: 'Avoid new Function(). Refactor to use static function definitions.',
    references: ['https://cwe.mitre.org/data/definitions/95.html'],
  },
  {
    regex: /innerHTML\s*=/g,
    title: 'Direct innerHTML Assignment',
    description: 'Assigning to innerHTML without sanitization can cause XSS.',
    severity: Severity.HIGH,
    cwe: 'CWE-79',
    recommendation: 'Use textContent for plain text or DOMPurify to sanitize HTML before assigning to innerHTML.',
    references: ['https://owasp.org/www-community/attacks/xss/'],
  },
  {
    regex: /document\.write\s*\(/g,
    title: 'Use of document.write()',
    description: 'document.write() with user-controlled data leads to XSS.',
    severity: Severity.HIGH,
    cwe: 'CWE-79',
    recommendation: 'Use DOM manipulation methods (createElement, appendChild) instead.',
    references: ['https://cwe.mitre.org/data/definitions/79.html'],
  },
  {
    regex: /\.exec\s*\(\s*[`'"].*\$\{/g,
    title: 'Potential Command Injection',
    description: 'Template literal interpolation inside exec() can lead to command injection.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-78',
    recommendation: 'Use execFile() with argument arrays or sanitize all inputs before passing to shell commands.',
    references: ['https://cwe.mitre.org/data/definitions/78.html'],
  },
  {
    regex: /\$where\s*:/g,
    title: 'MongoDB $where Operator Usage',
    description: '$where executes JavaScript on the MongoDB server and is a NoSQL injection vector.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-943',
    recommendation: 'Avoid $where. Use standard MongoDB query operators instead.',
    references: ['https://cwe.mitre.org/data/definitions/943.html'],
  },
  {
    regex: /query\s*\(\s*[`'"][^`'"]*\$\{/g,
    title: 'Potential SQL Injection via Template Literal',
    description: 'String interpolation in SQL queries can lead to SQL injection.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-89',
    recommendation: 'Use parameterized queries or prepared statements instead of string interpolation.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  {
    regex: /query\s*\(\s*["'][^"']*["']\s*\+/g,
    title: 'Potential SQL Injection via Concatenation',
    description: 'String concatenation in SQL queries can lead to SQL injection.',
    severity: Severity.CRITICAL,
    cwe: 'CWE-89',
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
  },
];

export function detectInjection(file: FileEntry): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split('\n');

  for (const rule of INJECTION_RULES) {
    rule.regex.lastIndex = 0;
    lines.forEach((lineContent, idx) => {
      const lineNum = idx + 1;
      const localRegex = new RegExp(rule.regex.source, rule.regex.flags.replace('g', '') + 'g');
      let match: RegExpExecArray | null;
      while ((match = localRegex.exec(lineContent)) !== null) {
        findings.push({
          id: generateFindingId(file.path, lineNum, rule.cwe),
          category: FindingCategory.INJECTION,
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

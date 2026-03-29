import { describe, it, expect } from 'vitest';
import { detectInjection } from '../../analyzers/sast/rules/injection-rules.js';

describe('detectInjection', () => {
  it('detects eval()', () => {
    const file = { path: 'test.ts', content: 'eval(userInput);' };
    const findings = detectInjection(file);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].cwe).toBe('CWE-95');
  });

  it('detects new Function()', () => {
    const file = { path: 'test.ts', content: 'const fn = new Function("return 1")' };
    const findings = detectInjection(file);
    expect(findings.some(f => f.title.includes('Dynamic Function'))).toBe(true);
  });

  it('detects innerHTML assignment', () => {
    const file = { path: 'test.ts', content: 'element.innerHTML = userInput;' };
    const findings = detectInjection(file);
    expect(findings.some(f => f.cwe === 'CWE-79')).toBe(true);
  });

  it('detects SQL injection via template literal', () => {
    const file = { path: 'test.ts', content: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)' };
    const findings = detectInjection(file);
    expect(findings.some(f => f.cwe === 'CWE-89')).toBe(true);
  });

  it('detects MongoDB $where', () => {
    const file = { path: 'test.ts', content: 'db.find({ $where: "this.age > 18" })' };
    const findings = detectInjection(file);
    expect(findings.some(f => f.cwe === 'CWE-943')).toBe(true);
  });

  it('does not flag safe parameterized queries', () => {
    const file = { path: 'test.ts', content: 'db.query("SELECT * FROM users WHERE id = $1", [userId])' };
    const findings = detectInjection(file);
    expect(findings.filter(f => f.cwe === 'CWE-89')).toHaveLength(0);
  });
});

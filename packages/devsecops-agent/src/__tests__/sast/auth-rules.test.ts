import { describe, it, expect } from 'vitest';
import { detectAuthIssues } from '../../analyzers/sast/rules/auth-rules.js';

describe('detectAuthIssues', () => {
  it('detects jwt.decode without verify', () => {
    const file = { path: 'auth.ts', content: 'const data = jwt.decode(token);' };
    const findings = detectAuthIssues(file);
    expect(findings.some(f => f.cwe === 'CWE-347')).toBe(true);
  });

  it('detects hardcoded JWT secret', () => {
    const file = { path: 'auth.ts', content: 'jwt.sign(payload, "mysecretkey123456")' };
    const findings = detectAuthIssues(file);
    expect(findings.some(f => f.cwe === 'CWE-798')).toBe(true);
  });

  it('detects dangerouslySetInnerHTML', () => {
    const file = { path: 'comp.tsx', content: '<div dangerouslySetInnerHTML={{ __html: content }} />' };
    const findings = detectAuthIssues(file);
    expect(findings.some(f => f.cwe === 'CWE-79')).toBe(true);
  });

  it('detects cors wildcard origin', () => {
    const file = { path: 'server.ts', content: 'app.use(cors({ origin: "*" }))' };
    const findings = detectAuthIssues(file);
    expect(findings.some(f => f.cwe === 'CWE-942')).toBe(true);
  });

  it('detects MD5 usage', () => {
    const file = { path: 'crypto.ts', content: 'createHash("md5").update(password).digest("hex")' };
    const findings = detectAuthIssues(file);
    expect(findings.some(f => f.cwe === 'CWE-328')).toBe(true);
  });

  it('does not flag jwt.verify', () => {
    const file = { path: 'auth.ts', content: 'const data = jwt.verify(token, secret);' };
    const findings = detectAuthIssues(file);
    expect(findings.filter(f => f.cwe === 'CWE-347')).toHaveLength(0);
  });
});

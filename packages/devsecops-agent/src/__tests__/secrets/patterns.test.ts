import { describe, it, expect } from 'vitest';
import { SecretsAnalyzer } from '../../analyzers/secrets/index.js';

const analyzer = new SecretsAnalyzer();

async function scan(code: string) {
  return analyzer.analyze({ files: [{ path: 'test.ts', content: code }], rootDir: '.' });
}

describe('SecretsAnalyzer patterns', () => {
  it('detects AWS Access Key ID', async () => {
    const report = await scan('const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(report.some(f => f.title === 'AWS Access Key ID')).toBe(true);
  });

  it('detects GitHub PAT', async () => {
    const report = await scan('const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789A";');
    expect(report.some(f => f.title === 'GitHub Personal Access Token')).toBe(true);
  });

  it('detects private key header', async () => {
    const report = await scan('const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...";');
    expect(report.some(f => f.title === 'Private Key')).toBe(true);
  });

  it('detects database connection string', async () => {
    const report = await scan('const url = "postgres://admin:password123@db.example.com:5432/mydb";');
    expect(report.some(f => f.title === 'Database Connection String')).toBe(true);
  });

  it('does not flag comment lines', async () => {
    const report = await scan('// const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(report).toHaveLength(0);
  });

  it('redacts secrets in codeSnippet', async () => {
    const report = await scan('const key = "AKIAIOSFODNN7EXAMPLE";');
    const finding = report.find(f => f.title === 'AWS Access Key ID');
    expect(finding?.codeSnippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});

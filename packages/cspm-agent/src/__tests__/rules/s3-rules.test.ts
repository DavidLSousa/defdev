import { describe, it, expect, beforeAll } from 'vitest';
import { IaCResource, Severity } from '@defdev/core';
import { runAllRules } from '../../rules/index.js';
import '../../rules/s3-rules.js';

function makeS3(name: string, props: Record<string, unknown>): IaCResource {
  return { type: 'aws_s3_bucket', name, properties: props, file: 'main.tf', lineStart: 1, lineEnd: 10 };
}

describe('S3 compliance rules', () => {
  it('flags public-read ACL as CRITICAL', () => {
    const violations = runAllRules([makeS3('my_bucket', { acl: 'public-read' })]);
    const v = violations.find((v) => v.rule === 'S3-001');
    expect(v).toBeDefined();
    expect(v?.severity).toBe(Severity.CRITICAL);
  });

  it('does not flag private ACL', () => {
    const violations = runAllRules([makeS3('my_bucket', { acl: 'private' })]);
    expect(violations.find((v) => v.rule === 'S3-001')).toBeUndefined();
  });

  it('flags bucket without encryption as HIGH', () => {
    const violations = runAllRules([makeS3('my_bucket', {})]);
    const v = violations.find((v) => v.rule === 'S3-002');
    expect(v).toBeDefined();
    expect(v?.severity).toBe(Severity.HIGH);
  });

  it('does not flag bucket with encryption configured', () => {
    const violations = runAllRules([
      makeS3('my_bucket', {
        server_side_encryption_configuration: { rule: { apply_server_side_encryption_by_default: { sse_algorithm: 'AES256' } } },
      }),
    ]);
    expect(violations.find((v) => v.rule === 'S3-002')).toBeUndefined();
  });

  it('flags bucket without versioning as MEDIUM', () => {
    const violations = runAllRules([makeS3('my_bucket', {})]);
    const v = violations.find((v) => v.rule === 'S3-003');
    expect(v?.severity).toBe(Severity.MEDIUM);
  });

  it('includes remediation code for violations', () => {
    const violations = runAllRules([makeS3('my_bucket', { acl: 'public-read' })]);
    expect(violations[0].remediation.code).toBeDefined();
  });
});

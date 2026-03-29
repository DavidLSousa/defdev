import { describe, it, expect } from 'vitest';
import { IaCResource, Severity } from '@defdev/core';
import { runAllRules } from '../../rules/index.js';
import '../../rules/security-group-rules.js';

function makeSg(name: string, props: Record<string, unknown>): IaCResource {
  return { type: 'aws_security_group', name, properties: props, file: 'sg.tf', lineStart: 1, lineEnd: 20 };
}

describe('Security Group compliance rules', () => {
  it('flags SSH open to world as CRITICAL', () => {
    const violations = runAllRules([makeSg('web_sg', {
      ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }],
    })]);
    const v = violations.find((v) => v.rule === 'SG-001');
    expect(v).toBeDefined();
    expect(v?.severity).toBe(Severity.CRITICAL);
  });

  it('does not flag SSH restricted to specific IP', () => {
    const violations = runAllRules([makeSg('web_sg', {
      ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['10.0.0.1/32'] }],
    })]);
    expect(violations.find((v) => v.rule === 'SG-001')).toBeUndefined();
  });

  it('flags RDP open to world as CRITICAL', () => {
    const violations = runAllRules([makeSg('win_sg', {
      ingress: [{ from_port: 3389, to_port: 3389, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }],
    })]);
    expect(violations.find((v) => v.rule === 'SG-002')).toBeDefined();
  });

  it('flags all-traffic ingress as CRITICAL', () => {
    const violations = runAllRules([makeSg('open_sg', {
      ingress: [{ protocol: '-1', cidr_blocks: ['0.0.0.0/0'] }],
    })]);
    expect(violations.find((v) => v.rule === 'SG-003')).toBeDefined();
  });
});

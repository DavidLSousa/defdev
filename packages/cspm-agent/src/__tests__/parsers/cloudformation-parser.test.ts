import { describe, it, expect } from 'vitest';
import { CloudFormationParser } from '../../parsers/cloudformation-parser.js';

const parser = new CloudFormationParser();

const SAMPLE_CFN = `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-vulnerable-bucket
      AccessControl: PublicRead
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Web security group
`;

describe('CloudFormationParser', () => {
  it('supports .yaml and .yml files', () => {
    expect(parser.supports('infra.yaml')).toBe(true);
    expect(parser.supports('infra.yml')).toBe(true);
    expect(parser.supports('main.tf')).toBe(false);
  });

  it('parses resources from CloudFormation YAML', async () => {
    const resources = await parser.parse(SAMPLE_CFN, 'stack.yaml');
    expect(resources.length).toBe(2);
  });

  it('normalizes CloudFormation type to terraform-like name', async () => {
    const resources = await parser.parse(SAMPLE_CFN, 'stack.yaml');
    const bucket = resources.find((r) => r.name === 'MyBucket');
    expect(bucket?.type).toBe('aws_s3_bucket');
  });

  it('preserves properties', async () => {
    const resources = await parser.parse(SAMPLE_CFN, 'stack.yaml');
    const bucket = resources.find((r) => r.name === 'MyBucket');
    expect(bucket?.properties['BucketName']).toBe('my-vulnerable-bucket');
  });

  it('returns empty array for invalid YAML', async () => {
    const resources = await parser.parse('{ invalid yaml: [unclosed', 'bad.yaml');
    expect(resources).toHaveLength(0);
  });
});

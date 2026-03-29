import { Severity } from '@defdev/core';
import { registerRule, makeViolation, ComplianceRule } from './index.js';

const s3PublicAcl: ComplianceRule = {
  id: 'S3-001',
  name: 'S3 Bucket Public ACL',
  description: 'S3 bucket should not have a public ACL.',
  severity: Severity.CRITICAL,
  resourceTypes: ['aws_s3_bucket'],
  frameworks: { CIS: '2.1.1' },
  check(resource) {
    const acl = resource.properties['acl'] as string | undefined;
    if (acl === 'public-read' || acl === 'public-read-write') {
      return makeViolation(
        this, resource,
        `S3 bucket "${resource.name}" has public ACL: "${acl}".`,
        'All objects in this bucket may be publicly accessible, exposing sensitive data.',
        'Set acl to "private" and use bucket policies to grant specific access.',
        `resource "aws_s3_bucket" "${resource.name}" {\n  # Remove: acl = "${acl}"\n}\n\nresource "aws_s3_bucket_acl" "${resource.name}_acl" {\n  bucket = aws_s3_bucket.${resource.name}.id\n  acl    = "private"\n}`
      );
    }
    return null;
  },
};

const s3NoEncryption: ComplianceRule = {
  id: 'S3-002',
  name: 'S3 Bucket Without Server-Side Encryption',
  description: 'S3 bucket should have server-side encryption enabled.',
  severity: Severity.HIGH,
  resourceTypes: ['aws_s3_bucket', 'aws_s3_bucket_server_side_encryption_configuration'],
  frameworks: { CIS: '2.1.2' },
  check(resource) {
    if (resource.type !== 'aws_s3_bucket') return null;
    const encryption = resource.properties['server_side_encryption_configuration'];
    if (!encryption) {
      return makeViolation(
        this, resource,
        `S3 bucket "${resource.name}" does not have server-side encryption configured.`,
        'Data at rest is unencrypted, violating data protection requirements.',
        'Add server_side_encryption_configuration with AES256 or aws:kms.',
        `resource "aws_s3_bucket_server_side_encryption_configuration" "${resource.name}_encryption" {\n  bucket = aws_s3_bucket.${resource.name}.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}`
      );
    }
    return null;
  },
};

const s3NoVersioning: ComplianceRule = {
  id: 'S3-003',
  name: 'S3 Bucket Without Versioning',
  description: 'S3 bucket should have versioning enabled.',
  severity: Severity.MEDIUM,
  resourceTypes: ['aws_s3_bucket'],
  frameworks: { CIS: '2.1.3' },
  check(resource) {
    const versioning = resource.properties['versioning'] as Record<string, unknown> | undefined;
    if (!versioning || versioning['enabled'] !== true) {
      return makeViolation(
        this, resource,
        `S3 bucket "${resource.name}" does not have versioning enabled.`,
        'Without versioning, accidental deletions or overwrites cannot be recovered.',
        'Enable versioning to protect against accidental data loss.',
        `resource "aws_s3_bucket_versioning" "${resource.name}_versioning" {\n  bucket = aws_s3_bucket.${resource.name}.id\n  versioning_configuration {\n    status = "Enabled"\n  }\n}`
      );
    }
    return null;
  },
};

const s3NoPublicAccessBlock: ComplianceRule = {
  id: 'S3-004',
  name: 'S3 Bucket Without Public Access Block',
  description: 'S3 bucket should have the public access block configuration enabled.',
  severity: Severity.HIGH,
  resourceTypes: ['aws_s3_bucket'],
  frameworks: { CIS: '2.1.5' },
  check(resource) {
    const pab = resource.properties['public_access_block'] ??
      resource.properties['block_public_acls'];
    if (!pab) {
      return makeViolation(
        this, resource,
        `S3 bucket "${resource.name}" is missing public access block configuration.`,
        'Without the public access block, future misconfiguration could expose bucket contents.',
        'Add aws_s3_bucket_public_access_block with all options set to true.',
        `resource "aws_s3_bucket_public_access_block" "${resource.name}_pab" {\n  bucket                  = aws_s3_bucket.${resource.name}.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`
      );
    }
    return null;
  },
};

registerRule(s3PublicAcl);
registerRule(s3NoEncryption);
registerRule(s3NoVersioning);
registerRule(s3NoPublicAccessBlock);

import yaml from 'js-yaml';
import { IaCResource } from '@defdev/core';
import { IaCParser } from './types.js';

interface CfnTemplate {
  Resources?: Record<string, {
    Type: string;
    Properties?: Record<string, unknown>;
  }>;
}

export class CloudFormationParser implements IaCParser {
  supports(filePath: string): boolean {
    return filePath.endsWith('.yaml') || filePath.endsWith('.yml');
  }

  async parse(content: string, filePath: string): Promise<IaCResource[]> {
    let template: CfnTemplate;
    try {
      template = yaml.load(content) as CfnTemplate;
    } catch (err) {
      console.warn(`[CSPM] Failed to parse CloudFormation file: ${filePath}`, (err as Error).message);
      return [];
    }

    if (!template?.Resources) return [];

    const resources: IaCResource[] = [];
    const lines = content.split('\n');

    for (const [logicalId, resource] of Object.entries(template.Resources)) {
      const cfnType = resource.Type ?? '';
      // Convert CloudFormation type to Terraform-like naming for unified rule matching
      // e.g. AWS::S3::Bucket -> aws_s3_bucket
      const normalizedType = this.normalizeCfnType(cfnType);

      // Find approximate line number
      const lineStart = this.findLineNumber(lines, logicalId);

      resources.push({
        type: normalizedType,
        name: logicalId,
        properties: {
          ...resource.Properties,
          _cfnType: cfnType,
        },
        file: filePath,
        lineStart,
        lineEnd: lineStart,
      });
    }

    return resources;
  }

  private normalizeCfnType(cfnType: string): string {
    return cfnType
      .replace(/^AWS::/, '')
      .replace(/::/g, '_')
      .toLowerCase()
      .replace(/^/, 'aws_');
  }

  private findLineNumber(lines: string[], logicalId: string): number {
    const idx = lines.findIndex((l) => l.includes(logicalId + ':'));
    return idx >= 0 ? idx + 1 : 1;
  }
}

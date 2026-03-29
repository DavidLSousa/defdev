import { exec } from 'child_process';
import { promisify } from 'util';
import { IaCResource } from '@defdev/core';
import { IaCParser } from './types.js';

const execAsync = promisify(exec);

type TerraformJson = Record<string, Record<string, Record<string, unknown>>>;

export class TerraformParser implements IaCParser {
  supports(filePath: string): boolean {
    return filePath.endsWith('.tf');
  }

  async parse(content: string, filePath: string): Promise<IaCResource[]> {
    try {
      return await this.parseWithHcl2Json(content, filePath);
    } catch {
      return this.parseWithRegex(content, filePath);
    }
  }

  private async parseWithHcl2Json(content: string, filePath: string): Promise<IaCResource[]> {
    const { stdout } = await execAsync(`echo '${content.replace(/'/g, "'\\''")}' | hcl2json`, {
      timeout: 10000,
    });

    const parsed = JSON.parse(stdout) as TerraformJson;
    return this.extractResources(parsed, filePath);
  }

  private parseWithRegex(content: string, filePath: string): IaCResource[] {
    const resources: IaCResource[] = [];
    // Match: resource "aws_s3_bucket" "my_bucket" { ... }
    const resourceRegex = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
    const lines = content.split('\n');

    let match: RegExpExecArray | null;
    while ((match = resourceRegex.exec(content)) !== null) {
      const resourceType = match[1];
      const resourceName = match[2];
      const matchStart = content.lastIndexOf('\n', match.index) + 1;
      const lineStart = content.slice(0, match.index).split('\n').length;

      // Extract the block content (simple brace counting)
      const blockStart = content.indexOf('{', match.index);
      const properties = this.extractBlock(content, blockStart);

      resources.push({
        type: resourceType,
        name: resourceName,
        properties,
        file: filePath,
        lineStart,
        lineEnd: lineStart + (JSON.stringify(properties, null, 2).split('\n').length),
      });
    }

    return resources;
  }

  private extractBlock(content: string, start: number): Record<string, unknown> {
    let depth = 0;
    let i = start;
    while (i < content.length) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') {
        depth--;
        if (depth === 0) break;
      }
      i++;
    }
    const block = content.slice(start + 1, i);
    return this.parseHclBlock(block);
  }

  private parseHclBlock(block: string): Record<string, unknown> {
    const props: Record<string, unknown> = {};
    // Simple key = "value" or key = true/false/number extraction
    const kvRegex = /(\w+)\s*=\s*(?:"([^"]*)"|(true|false)|([\d.]+))/g;
    let m: RegExpExecArray | null;
    while ((m = kvRegex.exec(block)) !== null) {
      const key = m[1];
      const value = m[2] ?? (m[3] === 'true' ? true : m[3] === 'false' ? false : Number(m[4]));
      props[key] = value;
    }
    // Extract nested blocks
    const blockRegex = /(\w+)\s*\{([^}]*)\}/g;
    let bm: RegExpExecArray | null;
    while ((bm = blockRegex.exec(block)) !== null) {
      props[bm[1]] = this.parseHclBlock(bm[2]);
    }
    return props;
  }

  private extractResources(parsed: TerraformJson, filePath: string): IaCResource[] {
    const resources: IaCResource[] = [];
    const resourceSection = parsed['resource'] ?? {};

    for (const [resourceType, instances] of Object.entries(resourceSection)) {
      for (const [resourceName, properties] of Object.entries(instances)) {
        resources.push({
          type: resourceType,
          name: resourceName,
          properties: properties as Record<string, unknown>,
          file: filePath,
          lineStart: 1,
          lineEnd: 1,
        });
      }
    }

    return resources;
  }
}

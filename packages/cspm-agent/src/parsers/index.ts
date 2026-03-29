import { IaCParser } from './types.js';
import { TerraformParser } from './terraform-parser.js';
import { CloudFormationParser } from './cloudformation-parser.js';

const parsers: IaCParser[] = [new TerraformParser(), new CloudFormationParser()];

export function getParser(filePath: string): IaCParser | null {
  return parsers.find((p) => p.supports(filePath)) ?? null;
}

export { TerraformParser, CloudFormationParser };
export type { IaCParser };

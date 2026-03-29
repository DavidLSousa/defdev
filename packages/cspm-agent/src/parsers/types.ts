import { IaCResource } from '@defdev/core';

export interface IaCParser {
  parse(content: string, filePath: string): Promise<IaCResource[]>;
  supports(filePath: string): boolean;
}

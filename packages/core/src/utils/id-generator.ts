import { createHash } from 'crypto';

export function generateFindingId(file: string, line: number, rule: string): string {
  return createHash('sha256')
    .update(`${file}:${line}:${rule}`)
    .digest('hex')
    .slice(0, 16);
}

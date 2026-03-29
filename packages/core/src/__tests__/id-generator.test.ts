import { describe, it, expect } from 'vitest';
import { generateFindingId } from '../utils/id-generator.js';

describe('generateFindingId', () => {
  it('returns a 16-char hex string', () => {
    const id = generateFindingId('src/foo.ts', 10, 'SQL_INJECTION');
    expect(id).toHaveLength(16);
    expect(id).toMatch(/^[0-9a-f]+$/);
  });

  it('is deterministic for the same inputs', () => {
    const a = generateFindingId('src/foo.ts', 10, 'SQL_INJECTION');
    const b = generateFindingId('src/foo.ts', 10, 'SQL_INJECTION');
    expect(a).toBe(b);
  });

  it('differs when any input changes', () => {
    const base = generateFindingId('src/foo.ts', 10, 'SQL_INJECTION');
    expect(generateFindingId('src/bar.ts', 10, 'SQL_INJECTION')).not.toBe(base);
    expect(generateFindingId('src/foo.ts', 11, 'SQL_INJECTION')).not.toBe(base);
    expect(generateFindingId('src/foo.ts', 10, 'EVAL_USAGE')).not.toBe(base);
  });
});

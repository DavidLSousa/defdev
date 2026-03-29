import { readFile } from 'fs/promises';
import { resolve } from 'path';
import fg from 'fast-glob';
import { FileEntry } from '../interfaces/analyzer.js';

export async function readProjectFiles(
  rootDir: string,
  patterns: string[],
  ignore: string[] = ['**/node_modules/**', '**/dist/**', '**/.git/**']
): Promise<FileEntry[]> {
  const paths = await fg(patterns, { cwd: rootDir, ignore, absolute: true });
  const entries = await Promise.all(
    paths.map(async (p) => ({
      path: p,
      content: await readFile(p, 'utf-8'),
    }))
  );
  return entries;
}

export async function readSingleFile(filePath: string): Promise<FileEntry> {
  const absolute = resolve(filePath);
  return {
    path: absolute,
    content: await readFile(absolute, 'utf-8'),
  };
}

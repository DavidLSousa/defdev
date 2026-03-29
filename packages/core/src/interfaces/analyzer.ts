import { Finding } from '../types/finding.js';

export interface FileEntry {
  path: string;
  content: string;
}

export interface AnalysisInput {
  files: FileEntry[];
  rootDir: string;
}

export interface IAnalyzer {
  analyze(input: AnalysisInput): Promise<Finding[]>;
}

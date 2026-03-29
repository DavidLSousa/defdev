export interface DevSecOpsConfig {
  rootDir: string;
  includePatterns: string[];
  excludePatterns: string[];
  enableSast: boolean;
  enableSecrets: boolean;
  enableSca: boolean;
  severityThreshold: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export const defaultConfig: Omit<DevSecOpsConfig, 'rootDir'> = {
  includePatterns: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
  excludePatterns: ['**/node_modules/**', '**/dist/**', '**/.git/**', '**/*.test.ts', '**/*.spec.ts'],
  enableSast: true,
  enableSecrets: true,
  enableSca: true,
  severityThreshold: 'info',
};

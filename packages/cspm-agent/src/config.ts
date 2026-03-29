export type IaCFramework = 'terraform' | 'cloudformation';
export type ComplianceFramework = 'CIS' | 'PCI-DSS' | 'HIPAA';

export interface CspmConfig {
  rootDir: string;
  frameworks: IaCFramework[];
  complianceFrameworks: ComplianceFramework[];
  includePatterns: string[];
  excludePatterns: string[];
}

export const defaultConfig: Omit<CspmConfig, 'rootDir'> = {
  frameworks: ['terraform', 'cloudformation'],
  complianceFrameworks: ['CIS'],
  includePatterns: ['**/*.tf', '**/*.yaml', '**/*.yml'],
  excludePatterns: ['**/node_modules/**', '**/.git/**', '**/vendor/**'],
};

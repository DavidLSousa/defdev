import { IaCResource, ComplianceViolation } from '../types/iac.js';

export interface IIaCAnalyzer {
  analyze(resources: IaCResource[]): Promise<ComplianceViolation[]>;
}

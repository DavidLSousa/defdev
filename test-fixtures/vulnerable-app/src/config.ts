// VULNERABILITY: Hardcoded AWS credentials
export const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
export const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// VULNERABILITY: Hardcoded GitHub token
export const GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789A';

// VULNERABILITY: Hardcoded API key
export const api_key = 'sk-abc123def456ghi789jkl012mno345pqr';

// VULNERABILITY: Database URL with credentials embedded
export const DATABASE_URL = 'postgres://root:SuperSecret123!@prod-db.company.com:5432/production';

// VULNERABILITY: MongoDB connection with credentials
export const MONGO_URL = 'mongodb://admin:password@mongo.company.com:27017/mydb';

// VULNERABILITY: Hardcoded password
export const password = 'P@ssword123!';

// SECURE: Reading from environment variable
export const JWT_SECRET = process.env.JWT_SECRET;

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// VULNERABILITY: Hardcoded JWT secret
const JWT_SECRET = 'mysupersecretkey123';

// VULNERABILITY: jwt.decode without verification
export function decodeToken(token: string) {
  return jwt.decode(token);
}

// VULNERABILITY: jwt.sign with hardcoded secret literal
export function generateToken(userId: string) {
  return jwt.sign({ userId }, 'hardcoded_secret_do_not_use');
}

// VULNERABILITY: MD5 for password hashing
export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: SHA1 for hashing
export function weakHash(data: string): string {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// VULNERABILITY: Math.random for token generation
export function generateSessionId(): string {
  return Math.random().toString(36).substring(2);
}

// SECURE: jwt.verify (no vulnerability)
export function verifyToken(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET as string);
}

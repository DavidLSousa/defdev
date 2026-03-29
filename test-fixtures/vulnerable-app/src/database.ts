import { Pool } from 'pg';

const pool = new Pool({ connectionString: 'postgres://admin:password123@db.example.com:5432/mydb' });

// VULNERABILITY: SQL Injection via string concatenation
export async function getUserById(userId: string) {
  const result = await pool.query('SELECT * FROM users WHERE id = ' + userId);
  return result.rows[0];
}

// VULNERABILITY: SQL Injection via template literal
export async function searchUsers(name: string) {
  const result = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  return result.rows;
}

// VULNERABILITY: NoSQL Injection via $where
export async function findUser(filter: Record<string, unknown>) {
  // Simulated MongoDB call
  return { $where: `this.role === '${filter.role}'` };
}

// SECURE: Parameterized query (no vulnerability)
export async function getUserByIdSafe(userId: string) {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  return result.rows[0];
}

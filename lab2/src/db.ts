import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { Pool } from 'pg';

dotenv.config();

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: process.env.DB_USER || process.env.USER,
        host: process.env.DB_HOST || 'localhost',
        database: process.env.DB_NAME || 'security_lab',
        password: process.env.DB_PASSWORD || process.env.PASSWORD,
        port: 5432,
        ssl: false,
      }
);

export async function initDb(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS demo_users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      pin VARCHAR(10) NOT NULL,
      display_name VARCHAR(100) NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_accounts (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(100) NOT NULL
    );
  `);

  const demoUsers = [
    ['admin', '1234', 'Demo Admin'],
    ['student', '2468', 'Demo Student'],
    ['guest', '9999', 'Demo Guest'],
  ];

  for (const [username, pin, displayName] of demoUsers) {
    await pool.query(
      `INSERT INTO demo_users (username, pin, display_name)
       VALUES ($1, $2, $3)
       ON CONFLICT (username) DO NOTHING`,
      [username, pin, displayName]
    );
  }

  const passwordHash = await bcrypt.hash('DemoPass!23', 12);
  await pool.query(
    `INSERT INTO auth_accounts (username, password_hash, display_name)
     VALUES ($1, $2, $3)
     ON CONFLICT (username) DO NOTHING`,
    ['demo-admin', passwordHash, 'Demo Administrator']
  );
}

export default pool;

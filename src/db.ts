import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: process.env.USER,
        host: process.env.DB_HOST || 'localhost',
        database: process.env.DB_NAME || 'passes_db',
        password: process.env.PASSWORD,
        port: 5432,
        ssl: false,
      }
);

export async function initDb() {
  const query = `
    CREATE TABLE IF NOT EXISTS passes (
      id UUID PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      document VARCHAR(255) NOT NULL,
      issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'CANCELLED'
    );
  `;
  try {
    await pool.query(query);
    console.log('Table passes created/exists.');
  } catch (error) {
    console.error('Error during database init:', error);
  }
}
export async function testConnection() {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('Successful connection and test query:', res.rows[0]?.now);
  } catch (error) {
    console.error('Error during database connection:', error);
  }
}

export default pool;
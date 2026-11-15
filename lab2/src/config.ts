import dotenv from 'dotenv';

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SECRET;

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('SECRET must contain at least 32 characters in production.');
}

export const config = {
  isProduction,
  port: Number.parseInt(process.env.PORT ?? '3000', 10),
  sessionSecret: sessionSecret ?? 'local-development-session-secret',
  sessionMaxAgeMs: 60 * 60 * 1000,
};

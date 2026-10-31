import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import { testConnection } from './db.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req: Request, res: Response) => {
  res.send('App started, waiting for DB');
});

app.listen(port, async () => {
  console.log(`Server running`);
  
  // Ovdje pozivamo provjeru baze
  await testConnection();
});
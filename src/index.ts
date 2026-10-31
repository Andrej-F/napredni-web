import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import pool,{ initDb, testConnection } from './db.js';
import oidc from 'express-openid-connect';

dotenv.config();

const {auth, requiresAuth} = oidc;
const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = process.env.PORT || 3000;

const config = {
    authRequired: false,
    idpLogout: true,
    secret: process.env.SECRET as string,
    baseURL: externalUrl as string,
    clientID: process.env.CLIENT_ID as string,
    issuerBaseURL: `https://${process.env.ISSUER_DOMAIN}`,
    clientSecret: process.env.CLIENT_SECRET as string,
    authorizationParams:{
        response_type:'code',
    },
}

const app = express();

app.set('views',path.join(__dirname,'views'));
app.set('view engine', 'pug');

app.use(express.urlencoded( {extended: true}));
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

app.use(auth(config));

app.get('/', async (req: Request, res: Response) => {
  const isAuthenticated = req.oidc.isAuthenticated();
  const user = req.oidc.user;

  let totalPasses = 0;
  let activePasses = 0;

  try {
    const totalResult = await pool.query('SELECT COUNT(*) FROM passes');
    const activeResult = await pool.query("SELECT COUNT(*) FROM passes WHERE status = 'ACTIVE'");

    totalPasses = parseInt(totalResult.rows[0]?.count ?? '0', 10);
    activePasses = parseInt(activeResult.rows[0]?.count ?? '0', 10);
  } catch (error) {
    console.error('Greška pri dohvatu statistike iz baze:', error);
  }

  res.render('index', {
    isAuthenticated,
    user,
    totalPasses,
    activePasses,
  });
});

app.get('/admin/passes', requiresAuth(), (req: Request, res: Response) => {
  res.send(`Dobrodošli na zaštićeno upravljanje propusnicama, ${req.oidc.user?.name || req.oidc.user?.sub}!`);
});
app.listen(port, async () => {
  console.log(`Server running`);
  
  // Ovdje pozivamo provjeru baze
  await testConnection();
  await initDb();
});
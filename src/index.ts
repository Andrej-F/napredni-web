import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import pool,{ initDb, testConnection } from './db.js';
import {auth as jwtAuth, requiredScopes} from 'express-oauth2-jwt-bearer';
import {auth as oidcAuth, requiresAuth} from 'express-openid-connect'
import {randomUUID} from 'crypto';
import QRCode from 'qrcode';
import {getToken, issuePass} from './task2/automat';

dotenv.config();

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = process.env.PORT || 3000;

const config = {
    authRequired: false,
    idpLogout: true,
    //secret: process.env.SECRET as string,
    baseURL: externalUrl as string,
    clientID: process.env.CLIENT_ID as string,
    issuerBaseURL: `https://${process.env.ISSUER_DOMAIN}/`,
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

app.use(oidcAuth(config));

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

app.get('/admin/passes', requiresAuth(), async (req: Request, res: Response) => {
  const ownerName = req.oidc.user?.name;

  if (!ownerName) {
    return res.status(400).send('Prijavljeni korisnik nema postavljeno ime.');
  }

  try {
    const result = await pool.query(
      `SELECT id, name, document, issued_at, status
       FROM passes
       WHERE name = $1
       ORDER BY issued_at DESC`,
      [ownerName]
    );

    res.render('admin-passes', {
      ownerName,
      passes: result.rows,
    });
  } catch (error) {
    console.error('Greška pri dohvatu korisnikovih propusnica:', error);
    res.status(500).send('Greška pri dohvatu propusnica.');
  }
});

app.post('/admin/passes', requiresAuth(), async (req: Request, res: Response) => {
  const ownerName = req.oidc.user?.name;
  const { document } = req.body as { document?: unknown };

  if (!ownerName) {
    return res.status(400).send('Prijavljeni korisnik nema postavljeno ime.');
  }

  if (typeof document !== 'string' || document.trim() === '') {
    return res.status(400).send('Polje "document" je obavezno.');
  }

  try {
    await pool.query(
      `INSERT INTO passes (id, name, document, issued_at, status)
       VALUES ($1, $2, $3, $4, $5)`,
      [randomUUID(), ownerName, document.trim(), new Date(), 'ACTIVE']
    );

    res.redirect('/admin/passes');
  } catch (error) {
    console.error('Greška pri izdavanju propusnice putem weba:', error);
    res.status(500).send('Greška pri izdavanju propusnice.');
  }
});

const allowedPassStatuses = new Set(['ACTIVE', 'CANCELLED']);

app.post('/admin/passes/:id/status', requiresAuth(), async (req: Request, res: Response) => {
  const ownerName = req.oidc.user?.name;
  const { status } = req.body as { status?: unknown };

  if (!ownerName) {
    return res.status(400).send('Prijavljeni korisnik nema postavljeno ime.');
  }

  if (typeof status !== 'string' || !allowedPassStatuses.has(status)) {
    return res.status(400).send('Nepoznat status propusnice.');
  }

  try {
    const result = await pool.query(
      `UPDATE passes
       SET status = $1
       WHERE id = $2 AND name = $3`,
      [status, req.params.id, ownerName]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Propusnica nije pronađena.');
    }

    res.redirect('/admin/passes');
  } catch (error) {
    console.error('Greška pri promjeni statusa propusnice:', error);
    res.status(500).send('Greška pri promjeni statusa propusnice.');
  }
});

app.post('/admin/passes/:id/delete', requiresAuth(), async (req: Request, res: Response) => {
  const ownerName = req.oidc.user?.name;

  if (!ownerName) {
    return res.status(400).send('Prijavljeni korisnik nema postavljeno ime.');
  }

  try {
    const result = await pool.query(
      'DELETE FROM passes WHERE id = $1 AND name = $2',
      [req.params.id, ownerName]
    );

    if (result.rowCount === 0) {
      return res.status(404).send('Propusnica nije pronađena.');
    }

    res.redirect('/admin/passes');
  } catch (error) {
    console.error('Greška pri brisanju propusnice:', error);
    res.status(500).send('Greška pri brisanju propusnice.');
  }
});

const checkJwt = jwtAuth({
    audience: process.env.AUDIENCE as string,
    issuerBaseURL: `https://${process.env.ISSUER_DOMAIN}/`,
    tokenSigningAlg: 'RS256',
    secret: '',
});
const checkReadScope = requiredScopes('read:passes');

app.get('/passes/:id', checkJwt, checkReadScope, async(req:Request, res:Response)=>{
    const passId = req.params.id;
    try{//let's hope noone tries to do sql injection on my app :DDDDDDDDDDDDDD
        const result = await pool.query('select * from passes where id = $1', [passId]);
        if(result.rows.length===0){
            return res.status(404).json({error:'Propusnica nije pronađena'});
        }
        const pass = result.rows[0];
        res.json({
            id:pass.id,
            name:pass.name,
            document:pass.document,
            issuedAt:pass.issued_at.toISOString(),
            status:pass.status,
        });
    } catch(error){
        console.error('Greška pri dohvatu propusnice putem API: ', error);
        res.status(500).json({error: 'Greška na poslužitelju'});
    }
});

const checkCreateScope = requiredScopes('create:passes');

app.post('/passes',checkJwt,checkCreateScope, async(req:Request, res:Response)=>{
    const {name,document} = req.body;
    if(!name || typeof name !=='string' || name.trim()==='' || !document || typeof document !=='string' || document.trim()===''){
        return res.status(400).json({error: 'Polja "name" i "document" su obavezna'});
    }
    const id = randomUUID();
    const issuedAt = new Date();
    const status = 'ACTIVE';
    try{
        await pool.query(
      'INSERT INTO passes (id, name, document, issued_at, status) VALUES ($1, $2, $3, $4, $5)',
      [id, name, document, issuedAt, status]
    );
    const publicInfoUrl = `${externalUrl}/info/${id}`;
    const qrBuffer = await QRCode.toBuffer(publicInfoUrl, { type: 'png' });

    const passUrl = `${externalUrl}/passes/${id}`;
    res.setHeader('Location', passUrl);

    res.status(201).type('image/png').send(qrBuffer);
    }catch(error){
        console.error('Greška pri stvaranju propusnice putem API: ', error);
        res.status(500).json({error: 'Greška na poslužitelju'});
    }
})

app.listen(port, async () => {
  console.log(`Server running`);
  
  // Ovdje pozivamo provjeru baze
  await testConnection();
  await initDb();
});
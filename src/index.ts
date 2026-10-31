import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import pool,{ initDb, testConnection } from './db.js';
import {auth as jwtAuth, requiredScopes} from 'express-oauth2-jwt-bearer';
import {auth as oidcAuth, requiresAuth} from 'express-openid-connect'
import {randomUUID} from 'crypto';
import QRCode from 'qrcode';

dotenv.config();

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

app.get('/admin/passes', requiresAuth(), (req: Request, res: Response) => {
  res.send(`Dobrodošli na zaštićeno upravljanje propusnicama, ${req.oidc.user?.name || req.oidc.user?.sub}!`);
});

const checkJwt = jwtAuth({
    audience: process.env.AUDIENCE as string,
    issuerBaseURL: `https://${process.env.ISSUER_DOMAIN}`,
    tokenSigningAlg: 'RS256',
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
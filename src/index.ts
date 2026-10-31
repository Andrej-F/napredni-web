import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { testConnection } from './db.js';
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

app.get('/', (req: Request, res: Response) => {
  let username: string | undefined;
  if(req.oidc.isAuthenticated()){
    username = req.oidc.user?.name ?? req.oidc.user?.sub;
  }
  res.render('index', {username});
});

app.get('/private',requiresAuth(),(req: Request, res: Response)=>{
    const user = JSON.stringify(req.oidc.user,null,2);
    res.render('private',{user});
})
app.listen(port, async () => {
  console.log(`Server running`);
  
  // Ovdje pozivamo provjeru baze
  await testConnection();
});
import express, { Request, Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import bcrypt from 'bcrypt';
import pool from './db.js';
import { initDb } from './db.js';
import { config } from './config.js';
import {
  isBoundedString,
  isRequestBody,
  MAX_PASSWORD_LENGTH,
  MAX_PIN_LENGTH,
  MAX_USERNAME_LENGTH,
} from './validation.js';
import {
  clearAttempts,
  isBlocked,
  recordFailedAttempt,
  secondsUntilUnblocked,
} from './rate-limit.js';

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: 'lax',
      maxAge: config.sessionMaxAgeMs,
      path: '/',
    },
  })
);

app.use((req, _res, next) => {
  req.session.sqlInjectionVulnerableMode ??= false;
  req.session.authenticationVulnerableMode ??= false;
  next();
});

function safeError(res: Response, status: number, error: string): void {
  res.status(status).json({ error });
}

function destroySession(req: Request, res: Response): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.destroy((error) => {
      res.clearCookie('connect.sid', {
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'lax',
        path: '/',
      });
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function regenerateSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

app.get('/', (_req, res) => {
  res.render('index');
});

app.post('/api/modes/sql-injection/toggle', (req, res) => {
  if (isRequestBody(req.body) && Object.keys(req.body).length > 0) {
    return safeError(res, 400, 'Za prebacivanje načina rada nije potrebno slati podatke.');
  }
  req.session.sqlInjectionVulnerableMode = !req.session.sqlInjectionVulnerableMode;
  res.json({ vulnerableMode: req.session.sqlInjectionVulnerableMode });
});

app.post('/api/modes/authentication/toggle', async (req, res, next) => {
  if (isRequestBody(req.body) && Object.keys(req.body).length > 0) {
    return safeError(res, 400, 'Za prebacivanje načina rada nije potrebno slati podatke.');
  }

  const sqlMode = req.session.sqlInjectionVulnerableMode ?? false;
  const nextAuthMode = !(req.session.authenticationVulnerableMode ?? false);

  try {
    await regenerateSession(req);
    req.session.sqlInjectionVulnerableMode = sqlMode;
    req.session.authenticationVulnerableMode = nextAuthMode;
    res.json({ vulnerableMode: nextAuthMode, authenticated: false });
  } catch (error) {
    next(error);
  }
});

app.post('/api/sql-injection/test', async (req, res, next) => {
  if (!isRequestBody(req.body)) {
    return safeError(res, 400, 'Tijelo zahtjeva mora biti JSON objekt.');
  }

  const { username, pin } = req.body;
  if (!isBoundedString(username, MAX_USERNAME_LENGTH) || !isBoundedString(pin, MAX_PIN_LENGTH)) {
    return safeError(res, 400, 'Korisničko ime i PIN moraju biti valjani tekstualni podaci.');
  }

  const vulnerableMode = req.session.sqlInjectionVulnerableMode ?? false;

  try {
    const result = vulnerableMode
      ? await pool.query(
          `SELECT id, username, display_name
           FROM demo_users
           WHERE username = '${username}' AND pin = '${pin}'`
        )
      : await pool.query(
          `SELECT id, username, display_name
           FROM demo_users
           WHERE username = $1 AND pin = $2`, // zastita od obicne tautologije
          [username, pin] // rezultat je da SQL tretira 'sql injection' kao cisti tekst
        );

    const record = result.rows[0];
    if (!record) {
      return res.json({ //extra poruke u jsonu su ostavljene za vidjeti pozadinu
        success: false,
        mode: vulnerableMode ? 'vulnerable' : 'secure',
        message: vulnerableMode
          ? 'Upit nije vratio nijedan zapis.'
          : 'Unos je tretiran kao podatak i nije pronađen odgovarajući zapis.', 
        recordCount: 0,
        rows: result.rows,
      });
    }

    res.json({
      success: true,
      mode: vulnerableMode ? 'vulnerable' : 'secure',
      message: vulnerableMode
        ? 'Tautologija je promijenila logiku upita i demonstracijski upit je vratio zapis.'
        : 'Parametrizirani upit je uspješno pronašao odgovarajući demonstracijski zapis.',
      recordCount: result.rowCount,
      rows: result.rows,
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  if (!isRequestBody(req.body)) {
    return safeError(res, 400, 'Tijelo zahtjeva mora biti JSON objekt.');
  }

  const { username, password } = req.body;
  if (
    !isBoundedString(username, MAX_USERNAME_LENGTH) ||
    !isBoundedString(password, MAX_PASSWORD_LENGTH)
  ) {
    return safeError(res, 400, 'Korisničko ime i lozinka moraju biti valjani tekstualni podaci.');
  }

  const vulnerableMode = req.session.authenticationVulnerableMode ?? false;
  const clientIp = req.ip ?? 'unknown';

  if (!vulnerableMode && isBlocked(clientIp, username)) {
    return res.status(429).json({
      error: 'Previše neuspješnih pokušaja. Pokušajte ponovno za nekoliko minuta.',
      retryAfterSeconds: secondsUntilUnblocked(clientIp, username),
    });
  }

  try {
    const result = await pool.query(
      `SELECT username, password_hash, display_name
       FROM auth_accounts
       WHERE username = $1`,
      [username]
    );
    const account = result.rows[0];
    const passwordMatches = account
      ? await bcrypt.compare(password, account.password_hash)
      : false;

    if (!account || !passwordMatches) {
      if (!vulnerableMode) {
        const state = recordFailedAttempt(clientIp, username);
        if (state.blockedUntil !== null) {
          return res.status(429).json({
            error: 'Previše neuspješnih pokušaja. Pokušajte ponovno za pet minuta.',
            retryAfterSeconds: secondsUntilUnblocked(clientIp, username),
          });
        }
      }
      return res.status(401).json({ error: 'Uneseni podaci za prijavu nisu ispravni.' });
    }

    clearAttempts(clientIp, username);
    const sqlMode = req.session.sqlInjectionVulnerableMode ?? false;
    await regenerateSession(req);
    req.session.authenticated = true;
    req.session.username = account.username;
    req.session.authenticationMode = vulnerableMode ? 'vulnerable' : 'secure';
    req.session.authenticationVulnerableMode = vulnerableMode;
    req.session.sqlInjectionVulnerableMode = sqlMode;

    res.json({
      success: true,
      message: vulnerableMode
        ? 'Prijava je uspješna. Zaštita od ponavljanih neuspješnih pokušaja nije uključena.'
        : 'Prijava je uspješna. Aktivna je zaštita od ponavljanih neuspješnih pokušaja.',
      username: account.username,
      mode: vulnerableMode ? 'vulnerable' : 'secure',
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    await destroySession(req, res);
    res.json({ authenticated: false });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: req.session.authenticated === true,
    username: req.session.authenticated ? req.session.username : undefined,
    mode: req.session.authenticationVulnerableMode ? 'vulnerable' : 'secure',
  });
});

app.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
  console.error('Neočekivana greška poslužitelja:', error);
  safeError(res, 500, 'Došlo je do greške na poslužitelju.');
});

async function start(): Promise<void> {
  await initDb();
  app.listen(config.port, '0.0.0.0', () => {
    console.log(`Web Security Lab server pokrenut na portu ${config.port}.`);
  });
}

start().catch((error: unknown) => {
  console.error('Pokretanje aplikacije nije uspjelo:', error);
  process.exitCode = 1;
});

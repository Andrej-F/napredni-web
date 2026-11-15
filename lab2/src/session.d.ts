import 'express-session';

declare module 'express-session' {
  interface SessionData {
    sqlInjectionVulnerableMode?: boolean;
    authenticationVulnerableMode?: boolean;
    authenticated?: boolean;
    username?: string;
    authenticationMode?: 'secure' | 'vulnerable';
  }
}

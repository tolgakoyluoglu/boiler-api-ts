declare namespace Express {
  interface Request {
    me?: { [index: string]: any }
  }
}

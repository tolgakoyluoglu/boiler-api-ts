import { NextFunction, Request, Response } from 'express'
import session from '../config/session'
import { internalServerError } from '../helpers/responses'

async function authenticate(req: Request, res: Response, next: NextFunction) {
  try {
    const { token } = req.cookies
    if (token) req.me = await session.get(token)

    next()
  } catch (error) {
    internalServerError(req, res, error)
  }
}

export default authenticate

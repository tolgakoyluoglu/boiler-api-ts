import { Request, Response } from 'express'
import { log } from './logger'

function missingParameters(_params: {}, message: string, optional = false) {
  const params = Object.entries(_params)
  const missing = params
    .map(([key, value]) => {
      if (value === undefined) return key
    })
    .filter((_) => _)

  if (optional && missing.length !== params.length) return null

  if (!missing.length) return null
  return {
    code: 400,
    message: `${message}: ${missing.join(', ')}.`,
  }
}

/**
 * @swagger
 * components:
 *   missingOptional:
 *     description: Bad request. At least one of the parameters in message is required.
 *     content:
 *       application/json:
 *         schema:
 *           example:
 *             code: 400
 *             message: 'Missing optional parameter(s): [parameters].'
 */
function missingOptional(params: {}) {
  return missingParameters(params, 'Missing optional parameter(s)', true)
}

/**
 * @swagger
 * components:
 *   missingRequired:
 *     description: Bad request. All parameters in message are required.
 *     content:
 *       application/json:
 *         schema:
 *           example:
 *             code: 400
 *             message: 'Missing required parameter(s): [parameters].'
 */
function missingRequired(params: any) {
  return missingParameters(params, 'Missing required parameter(s)')
}

/**
 * @swagger
 * components:
 *   internalServerError:
 *     description: Internal server error
 *     content:
 *       application/json:
 *         schema:
 *           example:
 *             code: 500
 *             message: Internal server error.
 */
const INTERNAL_SERVER_ERROR = {
  code: 500,
  message: 'Internal server error.',
}

function internalServerError(req: Request, res: Response, error: any) {
  log(error)
  res.status(INTERNAL_SERVER_ERROR.code).json(INTERNAL_SERVER_ERROR)
}

/**
 * @swagger
 * components:
 *   noContent:
 *     description: Successful request
 */
const NO_CONTENT = {
  code: 204,
}

/**
 * @swagger
 * components:
 *   notFound:
 *     description: Not found
 *     content:
 *       application/json:
 *         schema:
 *           example:
 *             code: 404
 *             message: '[resource] not found.'
 */
const NOT_FOUND = {
  code: 404,
  message: 'Not found.',
}

/**
 * @swagger
 * components:
 *   unauthorizedRequest:
 *     description: Unauthorized request
 *     content:
 *       application/json:
 *         schema:
 *           example:
 *             code: 401
 *             message: Unauthorized request.
 */
const UNAUTHORIZED = {
  code: 401,
  message: 'Unauthorized request',
}

const EMAIL_EXISTS = {
  code: 422,
  message: 'Username already registered.',
}

const EMAIL_PASSWORD_NOMATCH = {
  code: 401,
  message: "E-mail and password combination doesn't match.",
}

export {
  missingOptional,
  missingRequired,
  internalServerError,
  INTERNAL_SERVER_ERROR,
  UNAUTHORIZED,
  NOT_FOUND,
  NO_CONTENT,
  EMAIL_EXISTS,
  EMAIL_PASSWORD_NOMATCH,
}

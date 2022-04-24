import { typeOf } from '.'
import { NextFunction, Request, Response } from 'express'
import { email } from './regexp'

const blacklistRegexp = [email]
const blacklistKeys = ['password', 'passwordRepeat', 'newPassword', 'newPasswordRepeat']
const REDACTED = '*REDACTED*'

function redactString(input: string) {
  let result = input
  for (const re of blacklistRegexp) {
    if (re.test(input)) {
      result = REDACTED
    }
  }
  return result
}

function redactObject(input: any) {
  const result: any = {}
  for (const key in input) {
    const t = typeOf(input[key])
    if (t === 'object') {
      result[key] = redact(input[key])
      continue
    }

    if (blacklistKeys.includes(key)) {
      result[key] = REDACTED
      continue
    }

    result[key] = redact(input[key])
  }
  return result
}

function redactArray(input: any) {
  const result = []
  for (const key in input) {
    result.push(redact(input[key]))
  }
  return result
}

function redact(data: string) {
  const type = typeOf(data)
  let redacted: {}

  switch (type) {
    case 'object':
      redacted = redactObject(data)
      break
    case 'array' as any:
      redacted = redactArray(data)
      break
    case 'string':
      redacted = redactString(data)
      break

    default:
      redacted = data
  }

  return redacted
}

function log(...args: any) {
  console.log(...args)
}

function logRequests() {
  return function (req: Request, res: Response, next: NextFunction) {
    if (typeof req.body === 'object' && req.body !== null) {
      log(new Date())
      let { method, url } = req
      method = method.toUpperCase()
      log(`${method} ${url}`)

      if (Object.keys(req.cookies).length) {
        log('Cookies:')
        log(JSON.stringify(req.cookies, null, 2))
      }
      if (Object.keys(req.body).length) {
        log('Body:')
        const body = redact(req.body)
        log(JSON.stringify(body, null, 2))
      }
    }

    next()
  }
}

export { log, logRequests }

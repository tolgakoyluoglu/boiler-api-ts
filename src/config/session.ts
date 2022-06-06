const redis = require('./redis')

export interface SessionObject {
  id: string | undefined
}

async function set(token: string, data: SessionObject): Promise<string> {
  const sessionData = JSON.stringify(data)
  return redis.set(token, sessionData)
}

async function get(token: string) {
  const sessionData = await redis.get(token)
  return JSON.parse(sessionData)
}

async function del(token: string) {
  if (token !== undefined && token !== null) {
    return redis.del(token)
  }
}

export default {
  set,
  get,
  del,
}

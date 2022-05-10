const redis = require('redis')
import { promisify } from 'util'

const REDIS_PORT: number = parseInt(process.env.REDIS_PORT as string)
const REDIS_HOST: string = process.env.REDIS_HOST as string
const REDIS_USER: string = process.env.REDIS_USER as string

const clientOptions = {
  host: REDIS_HOST,
  user: REDIS_USER,
  port: REDIS_PORT,
}

const client = redis.createClient(clientOptions)
client.on('connect', () => {
  console.log('Connected to Redis.')
})

const set = promisify(client.set).bind(client)
const get = promisify(client.get).bind(client)
const del = promisify(client.del).bind(client)

export = {
  set,
  get,
  del,
}

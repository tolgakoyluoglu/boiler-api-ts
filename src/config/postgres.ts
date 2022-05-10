import { Pool } from 'pg'
import { log } from '../helpers/logger'

const user: string = process.env.POSTGRES_USER as string
const password: string = process.env.POSTGRES_PASSWORD as string
const port: number = parseInt(process.env.POSTGRES_PORT as string)
const database: string = process.env.POSTGRES_DATABASE as string
const host: string = process.env.POSTGRES_HOST as string

const pool = new Pool({
  user,
  password,
  host,
  port,
  database,
})
pool
  .connect()
  .then((response) => log('Connected to PostgreSQL'))
  .catch((error) => log(error))

export async function query(text: string, values?: any) {
  return pool.query(text, values)
}

export async function getClient() {
  const client: any = await pool.connect()
  const query = client.query
  const release = client.release

  const timeout = setTimeout(() => {
    console.error('A client has been checked out for more than 5 seconds!')
    console.error(`The last executed query on this client was: ${client.lastQuery}`)
  }, 5000)

  client.query = (...args: []) => {
    client.lastQuery = args
    return query.apply(client, args)
  }
  client.release = () => {
    clearTimeout(timeout)
    client.query = query
    client.release = release
    return release.apply(client)
  }

  return client
}

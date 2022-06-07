import { Sequelize } from 'sequelize'

const user: string = process.env.POSTGRES_USER as string
const password: string = process.env.POSTGRES_PASSWORD as string
const database: string = process.env.POSTGRES_DATABASE as string
const host: string = process.env.POSTGRES_HOST as string

export const sequelize = new Sequelize(database, user, password, {
  host,
  dialect: 'postgres',
  pool: {
    max: 100,
    min: 0,
    idle: 200000,
    acquire: 1000000,
  },
})

sequelize
  .authenticate()
  .then((response) => {
    console.log('Connected to sequelize')
  })
  .catch((error) => console.error('Error connecting to sequelize:', error))

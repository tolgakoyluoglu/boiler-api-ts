import { query } from '../config/postgres'
import bcrypt from 'bcryptjs'

class UserService {
  static async findOne(data: { username?: string; id?: string }) {
    const { username, id } = data
    const text = `SELECT * FROM users WHERE username = $1 OR id= $2`
    const values = [username, id]

    try {
      const result = await query(text, values)
      const user = result.rows[0]

      return user
    } catch (error) {
      throw error
    }
  }

  static async create(data: { username: string; password: string }) {
    const { username, password } = data
    const text = `
    INSERT INTO users (username, password)
      VALUES ($1, $2)
    RETURNING id, username
    `
    const values = [username, password]

    try {
      const result = await query(text, values)
      const user = result.rows[0]

      return user
    } catch (error) {
      throw error
    }
  }

  static async update(data: { id: string; sessions: string[] }) {
    const { id, sessions } = data
    const text = `
    UPDATE
      users
    SET
      sessions = $2
    WHERE
      id = $1
    RETURNING id, username
    `
    const values = [id, sessions]

    try {
      const result = await query(text, values)
      const user = result.rows[0]

      return user
    } catch (error) {
      throw error
    }
  }

  static async comparePassword(userPassword: string, password: string) {
    return bcrypt.compareSync(password, userPassword)
  }
}

export = UserService

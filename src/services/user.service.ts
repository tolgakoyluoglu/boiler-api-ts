import bcrypt from 'bcryptjs'
import { User } from '../models/user.model'
import { Op } from 'sequelize'

class UserService {
  static async findOne(data: { email?: string; id?: string }) {
    const { email = null, id = null } = data
    return await User.findOne({
      where: {
        [Op.or]: [{ email }, { id }],
      },
    })
  }

  static async create(data: { email: string; password: string }) {
    const { email, password } = data
    return await User.create({ email, password })
  }

  static async update(data: { id: string; sessions: string[] }) {
    const { id, sessions } = data
    return await User.update({ sessions }, { where: { id } })
  }

  static async comparePassword(userPassword: string, password: string) {
    return bcrypt.compareSync(password, userPassword)
  }
}

export default UserService

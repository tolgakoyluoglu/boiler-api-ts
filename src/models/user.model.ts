import * as Sequelize from 'sequelize'
import { sequelize } from '../config/sequelize'

export interface UserModel extends Sequelize.Model {
  id: any
  email: string
  password: string
  googleId: string
  firstname: string
  lastname: string
  sessions: string[]
}

export const User = sequelize.define<UserModel>(
  'user',
  {
    id: {
      type: Sequelize.UUID,
      defaultValue: Sequelize.UUIDV4,
      primaryKey: true,
    },
    email: {
      type: Sequelize.STRING,
      unique: true,
      allowNull: false,
    },
    password: {
      type: Sequelize.STRING,
    },
    googleId: {
      type: Sequelize.STRING,
      unique: true,
    },
    sessions: {
      type: Sequelize.ARRAY(Sequelize.STRING),
    },
    firstname: {
      type: Sequelize.STRING,
    },
    lastname: {
      type: Sequelize.STRING,
    },
  },
  { timestamps: false },
)

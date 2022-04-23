import {
  internalServerError,
  missingRequired,
  NOT_FOUND,
  USERNAME_EXIST,
  EMAIL_PASSWORD_NOMATCH,
  UNAUTHORIZED,
} from '../helpers/responses'
import { uuidv4 } from '../helpers'
import session from '../config/session'
import bcrypt from 'bcryptjs'
import { Request, Response } from 'express'
import User from '../types/user'
import { UserService } from '../services'

const { NODE_ENV } = process.env
const salt = bcrypt.genSaltSync(10)
const cookieConfig = {
  httpOnly: true,
  secure: NODE_ENV !== 'development',
}

/**
 * @swagger
 * components:
 *   user:
 *     type: object
 *     properties:
 *       username:
 *         type: string
 *         example: john
 *
 *   userResponse:
 *     type: object
 *     $ref: '#/components/user'
 *
 *   usersResponse:
 *     type: array
 *     items:
 *       $ref: '#/components/user'
 */
class UserController {
  /**
   * @swagger
   * /users/sign-up:
   *   post:
   *     tags: [Users]
   *     summary: Sign up
   *
   *     requestBody:
   *       description: The user to create.
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *               password:
   *                 type: string
   *             example:
   *               username: john
   *               password: '123456'
   *
   *     responses:
   *       200:
   *         description: User object
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/User'
   *       400:
   *         description: Bad request
   *       401:
   *         description: Unauthorized request
   *
   */
  static async signUp(req: Request, res: Response) {
    try {
      const { username, password } = req.body
      const ERROR = missingRequired({ username, password })
      if (ERROR) return res.status(ERROR.code).json(ERROR)

      const usernameExist: User = await UserService.findOne({ username })
      if (usernameExist) return res.status(USERNAME_EXIST.code).json(USERNAME_EXIST)

      const hashedPassword = bcrypt.hashSync(password, salt)
      const user: User = await UserService.create({ username, password: hashedPassword })
      console.log('')
      res.json(user)
    } catch (error) {
      internalServerError(req, res, error)
    }
  }

  /**
   * @swagger
   * /users/sign-in:
   *   post:
   *     tags: [Users]
   *     summary: Sign in
   *
   *     requestBody:
   *       description: User credentials.
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               username:
   *                 type: string
   *               password:
   *                 type: string
   *
   *             example:
   *               username: john
   *               password: '123456'
   *
   *     responses:
   *       200:
   *         description: User object
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/userResponse'
   *         headers:
   *           Set-Cookie:
   *             schema:
   *               type: string
   *               example: clientCookie=abcde12345; Path=/; HttpOnly
   *       400:
   *         description: Bad request
   *       401:
   *         description: Unauthorized request
   *
   */
  static async signIn(req: Request, res: Response) {
    try {
      const { username, password } = req.body
      const ERROR = missingRequired({ username, password })
      if (ERROR) return res.status(ERROR.code).json(ERROR)

      let user: User = await UserService.findOne({ username })
      if (!user) return res.status(NOT_FOUND.code).json(NOT_FOUND)

      const match = await UserService.comparePassword(user.password, password)
      if (!match) return res.status(EMAIL_PASSWORD_NOMATCH.code).json(EMAIL_PASSWORD_NOMATCH)

      const sessionData = { id: user.id }
      const token = uuidv4()

      await session.set(token, sessionData)
      res.cookie('token', token, cookieConfig)
      const sessionTokens = [token].concat(user.sessions)
      user = await UserService.update({ id: user.id, sessions: sessionTokens })

      res.json(user)
    } catch (error) {
      internalServerError(req, res, error)
    }
  }

  /**
   * @swagger
   * /users/authenticate:
   *   get:
   *     tags: [Users]
   *     summary: Authenticate user
   *
   *     responses:
   *       200:
   *         description: User object
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/userResponse'
   *       401:
   *         description: Unauthorized request
   *
   */
  static async authenticateRoute(req: Request, res: Response) {
    try {
      if (!req.me) return res.json(null)
      const { id } = req.me

      const user: User = await UserService.findOne({ id })
      if (!user) return res.status(UNAUTHORIZED.code).json(UNAUTHORIZED)

      user.sessions = []
      user.password = ''
      res.json(user)
    } catch (error) {
      internalServerError(req, res, error)
    }
  }

  /**
   * @swagger
   * /users/sign-out:
   *   get:
   *     tags: [Users]
   *     summary: Sign out
   *
   *     responses:
   *       204:
   *         description: No content
   *
   */
  static async signOut(req: Request, res: Response) {
    try {
      if (!req.me) return res.json(null)
      const { token } = req.cookies
      const { id } = req.me

      const user = await UserService.findOne(id)
      if (user) {
        let sessionTokens = user.sessions
        sessionTokens = sessionTokens.filter((t: string) => t !== token)
        user.sessions = sessionTokens
        await UserService.update({ id: user.id, sessions: sessionTokens })
      }
      await session.del(token)
      res.clearCookie('token')

      res.status(204).end()
    } catch (error) {
      internalServerError(req, res, error)
    }
  }
}

export = UserController

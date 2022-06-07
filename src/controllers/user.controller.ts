import {
  internalServerError,
  missingRequired,
  NOT_FOUND,
  EMAIL_EXISTS,
  EMAIL_PASSWORD_NOMATCH,
  UNAUTHORIZED,
} from '../helpers/responses'
import { uuidv4 } from '../helpers'
import session from '../config/session'
import bcrypt from 'bcryptjs'
import { Request, Response } from 'express'
import { UserService } from '../services'
import { google } from 'googleapis'
import axios from 'axios'
import { User } from '../models/user.model'

const { NODE_ENV } = process.env
const salt = bcrypt.genSaltSync(10)
const cookieConfig = {
  httpOnly: true,
  secure: NODE_ENV !== 'development',
}
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } = process.env
const REDIRECT_URL = 'http://localhost:4000/users/google/me'
const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URL)

/**
 * @swagger
 * components:
 *   user:
 *     type: object
 *     properties:
 *       email:
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
   *               email:
   *                 type: string
   *               password:
   *                 type: string
   *             example:
   *               email: john
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
      const { email, password } = req.body
      const ERROR = missingRequired({ email, password })
      if (ERROR) return res.status(ERROR.code).json(ERROR)

      const emailExist = await UserService.findOne({ email })
      if (emailExist) return res.status(EMAIL_EXISTS.code).json(EMAIL_EXISTS)

      const hashedPassword = bcrypt.hashSync(password, salt)
      const user = await UserService.create({ email, password: hashedPassword })

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
   *               email:
   *                 type: string
   *               password:
   *                 type: string
   *
   *             example:
   *               email: john
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
      const { email, password } = req.body
      const ERROR = missingRequired({ email, password })
      if (ERROR) return res.status(ERROR.code).json(ERROR)

      let user = await UserService.findOne({ email })
      if (!user) return res.status(NOT_FOUND.code).json(NOT_FOUND)

      const match = await UserService.comparePassword(user.password, password)
      if (!match) return res.status(EMAIL_PASSWORD_NOMATCH.code).json(EMAIL_PASSWORD_NOMATCH)

      const sessionData = { id: user.id }
      const token = uuidv4()

      await session.set(token, sessionData)
      res.cookie('token', token, cookieConfig)
      const sessionTokens = [token].concat(user.sessions)
      await UserService.update({ id: user.id, sessions: sessionTokens })

      user.password = ''
      user.sessions = []

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

      const user = await UserService.findOne({ id })
      if (!user) return res.status(UNAUTHORIZED.code).json(UNAUTHORIZED)

      // Don't leak sensitive data
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

  /**
   * @swagger
   * /users/google/me:
   *   get:
   *     tags: [Users]
   *     summary: Validate Google user with token
   *
   *     responses:
   *       200:
   *         description: Validate, create user and store cookie session
   *
   */
  static async getGoogleUser(req: Request, res: Response) {
    try {
      const code = req.query.code as string
      const { tokens } = await oauth2Client.getToken(code)

      const googleUser = await axios
        .get(`https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${tokens.access_token}`, {
          headers: {
            Authorization: `Bearer ${tokens.id_token}`,
          },
        })
        .then((res) => res.data)
        .catch((error) => {
          throw new Error(error)
        })

      let user = await UserService.findOne({ email: googleUser.email })
      if (!user) {
        const { googleId, email, firstname, lastname } = googleUser
        user = await User.create({
          email,
          googleId,
          firstname,
          lastname,
        })
      }

      const sessionData = { id: user.id }
      const token = uuidv4()

      await session.set(token, sessionData)
      res.cookie('auth_token', token, cookieConfig)
      const sessionTokens = [token].concat(user.sessions)
      await UserService.update({ id: user.id, sessions: sessionTokens })

      res.redirect('http://localhost:3000')
    } catch (error) {
      internalServerError(req, res, error)
    }
  }
}

export default UserController

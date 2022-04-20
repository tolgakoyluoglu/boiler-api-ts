const router = require('express').Router()
import users from './users'
import { Request, Response } from 'express'

router.get('/', (req: Request, res: Response) => {
  res.send('Api 200')
})
router.use('/users', users)

export default router

const router = require('express').Router()

import { Request, Response } from 'express'

router.get('/', (req: Request, res: Response) => {
  res.send('Api 200')
})

export default router

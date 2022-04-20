const router = require('express').Router()
import { UserController } from '../controllers'
import { AuthService } from '../services'

router.post('/sign-in', UserController.signIn)
router.post('/sign-up', UserController.signUp)
router.get('/sign-out', AuthService.authenticate, UserController.signOut)
router.get('/authenticate', AuthService.authenticate, UserController.authenticateRoute)

export default router

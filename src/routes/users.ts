const router = require('express').Router()
import { UserController } from '../controllers'
import authenticate from '../middlewares/authenticate'

router.post('/sign-in', UserController.signIn)
router.post('/sign-up', UserController.signUp)
router.get('/sign-out', authenticate, UserController.signOut)
router.get('/authenticate',authenticate, UserController.authenticateRoute)
router.get('/google/me', UserController.getGoogleUser)

export default router

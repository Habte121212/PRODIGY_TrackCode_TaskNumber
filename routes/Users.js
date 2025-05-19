const express = require('express')
const router = express.Router()
const {
  registerUser,
  loginUser,
  forgotPassword,
  resetPassword,
} = require('../controller/Users.js')

//register user
router.post('/register', registerUser)

//login user
router.post('/login', loginUser)

//forgot password
router.post('/forgot-password', forgotPassword)

//reset password
router.post('/reset-password/:token', resetPassword)

const registerRoutes = router
const loginUserRoutes = loginUser

module.exports = { registerRoutes, loginUserRoutes }

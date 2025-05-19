const User = require('../models/Users.js')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const { generateToken } = require('../utils/jwt')
const nodemailer = require('nodemailer')
const crypto = require('crypto')

// Register User
const registerUser = async (req, res) => {
  try {
    const { name, email, password, department, adminCode, role } = req.body

    // Field validations
    if (!name || !email || !password || !role) {
      return res
        .status(400)
        .json({ message: 'All required fields must be filled' })
    }
    if (role === 'manager' && !adminCode) {
      return res
        .status(400)
        .json({ message: 'Admin code is required for managers' })
    }
    if (role === 'employee' && !department) {
      return res
        .status(400)
        .json({ message: 'Department is required for employees' })
    }

    // username validations
    if (name.length < 3)
      return res
        .status(400)
        .json({ message: 'Name must be at least 3 characters long' })
    if (name.length > 20)
      return res
        .status(400)
        .json({ message: 'Name must be at most 20 characters long' })

    // email validations
    if (!validator.isEmail(email))
      return res.status(400).json({ message: 'Invalid email format' })

    // password validations (match frontend: min 6 chars)
    if (password.length < 6)
      return res
        .status(400)
        .json({ message: 'Password must be at least 6 characters' })

    // Check if user already exists
    let existingUser = await User.findOne({ email })
    if (existingUser)
      return res.status(400).json({ message: 'User already exists' })

    // Hash password
    const salt = await bcrypt.genSalt(10)
    let hashedPassword = await bcrypt.hash(password, salt)

    // Create new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      department: role === 'employee' ? department : '',
      adminCode: role === 'manager' ? adminCode : '',
      role,
    })

    // Save the user
    await newUser.save()
    res.status(201).json({ message: 'User registered successfully.' })
  } catch (error) {
    console.error(error)
    res
      .status(500)
      .json({ message: 'Internal server error. Please try again later.' })
  }
}

// login user
const loginUser = async (req, res) => {
  const { email, password } = req.body
  // Field validations
  if (!email || !password)
    return res.status(400).json({ message: 'All fields are required' })
  // Email validations
  if (!validator.isEmail(email))
    return res.status(400).json({ message: 'Invalid email format' })

  try {
    // check if user exists
    const foundUser = await User.findOne({ email })
    if (!foundUser)
      return res.status(400).json({ message: 'Invalid credentials' })

    // check if password is correct
    const isMatch = await bcrypt.compare(password, foundUser.password)
    if (!isMatch)
      return res.status(400).json({ message: 'Invalid credentials' })

    // Generate JWT token
    const token = generateToken({ id: foundUser.id, email: foundUser.email })

    // Set token as HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: 'none',
    })

    // send response
    return res
      .status(200)
      .json({ message: 'Login successful', role: foundUser.role })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error' })
  }
}

// forgot password
const forgotPassword = async (req, res) => {
  const { email } = req.body
  if (!email || !validator.isEmail(email)) {
    return res
      .status(400)
      .json({ message: 'Please enter a valid email address.' })
  }
  try {
    const foundUser = await User.findOne({ email })
    if (!foundUser) {
      // For security, do not reveal if user exists
      return res.status(200).json({
        message: 'A reset link has been sent.',
      })
    }

    // Generate a reset token and expiry (1 hour)
    const resetToken = crypto.randomBytes(32).toString('hex')
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex')
    foundUser.resetPasswordToken = resetTokenHash
    foundUser.resetPasswordExpires = Date.now() + 3600000 // 1 hour
    await foundUser.save()

    // Create reset URL using CLIENT_URL from .env
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`

    // Configure nodemailer
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    })

    // Email options
    const mailOptions = {
      from: `Employee Management <${process.env.EMAIL_USER}>`,
      to: foundUser.email,
      subject: 'Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you did not request this, please ignore this email.</p>`,
    }

    // Send email
    await transporter.sendMail(mailOptions)

    return res.status(200).json({
      message: 'A reset link has been sent.',
    })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error.' })
  }
}

// Reset Password
const resetPassword = async (req, res) => {
  const { token } = req.params
  const { password } = req.body
  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ message: 'Password must be at least 6 characters.' })
  }
  try {
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex')
    const user = await User.findOne({
      resetPasswordToken: resetTokenHash,
      resetPasswordExpires: { $gt: Date.now() },
    })
    if (!user) {
      return res
        .status(400)
        .json({ message: 'Invalid or expired reset token.' })
    }
    const salt = await bcrypt.genSalt(10)
    user.password = await bcrypt.hash(password, salt)
    user.resetPasswordToken = ''
    user.resetPasswordExpires = undefined
    await user.save()
    return res.status(200).json({ message: 'Password reset successful.' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Internal server error.' })
  }
}

module.exports = { registerUser, loginUser, forgotPassword, resetPassword }

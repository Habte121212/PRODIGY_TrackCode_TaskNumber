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

// Get all employees (for manager and employee view-only page)
router.get('/employees', async (req, res) => {
  try {
    const employees = await require('../models/Users').find(
      { role: 'employee' },
      'name email department',
    )
    res.status(200).json({ employees })
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch employees.' })
  }
})

// Create a new employee (manager only)
router.post('/employee', async (req, res) => {
  try {
    const { name, email, department, password } = req.body
    if (!name || !email || !department || !password) {
      return res.status(400).json({ message: 'All fields are required.' })
    }
    const User = require('../models/Users')
    const existing = await User.findOne({ email })
    if (existing) {
      return res
        .status(400)
        .json({ message: 'Employee with this email already exists.' })
    }
    const bcrypt = require('bcryptjs')
    const hashedPassword = await bcrypt.hash(password, 10)
    const newEmp = new User({
      name,
      email,
      department,
      password: hashedPassword,
      role: 'employee',
    })
    await newEmp.save()
    res.status(201).json({ message: 'Employee created successfully.' })
  } catch (err) {
    res.status(500).json({ message: 'Failed to create employee.' })
  }
})

// Update employee (manager only)
router.put('/employee/:id', async (req, res) => {
  try {
    const { name, email, department } = req.body
    const User = require('../models/Users')
    const emp = await User.findById(req.params.id)
    if (!emp) return res.status(404).json({ message: 'Employee not found.' })
    emp.name = name || emp.name
    emp.email = email || emp.email
    emp.department = department || emp.department
    await emp.save()
    res.status(200).json({ message: 'Employee updated successfully.' })
  } catch (err) {
    res.status(500).json({ message: 'Failed to update employee.' })
  }
})

// Get single employee details (manager only)
router.get('/employee/:id', async (req, res) => {
  try {
    const User = require('../models/Users')
    const emp = await User.findById(req.params.id, 'name email department')
    if (!emp) return res.status(404).json({ message: 'Employee not found.' })
    res.status(200).json({ employee: emp })
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch employee.' })
  }
})

// Delete employee (manager only)
router.delete('/employee/:id', async (req, res) => {
  try {
    const User = require('../models/Users')
    const emp = await User.findByIdAndDelete(req.params.id)
    if (!emp) return res.status(404).json({ message: 'Employee not found.' })
    res.status(200).json({ message: 'Employee deleted successfully.' })
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete employee.' })
  }
})

const registerRoutes = router
const loginUserRoutes = loginUser

module.exports = { registerRoutes, loginUserRoutes }

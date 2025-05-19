// Load environment variables
const dotenv = require('dotenv')
dotenv.config()

const express = require('express')
const { registerRoutes, loginUserRoutes } = require('./routes/Users')
const cors = require('cors')
// Database connection
const connectDB = require('./db/dbConfig')

connectDB()

// Initialize Express app
const app = express()
app.use(express.json())

//middleware
app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://localhost:5175',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5175',
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  }),
)

// routes
app.use('/server/users', registerRoutes)
app.post('/server/users/', loginUserRoutes)

// Start server
app.listen(8500, () => {
  console.log('server is running on port 8500')
})

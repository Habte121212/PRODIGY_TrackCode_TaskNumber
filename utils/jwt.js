const jwt = require('jsonwebtoken')
const JWT_SECRET = process.env.JWT_SECRET

function generateToken(data) {
  return jwt.sign(data, JWT_SECRET, { expiresIn: '1d' })
}
// verify token
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET)
}

module.exports = { generateToken, verifyToken }

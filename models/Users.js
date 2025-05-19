const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      minlength: 3,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    department: {
      type: String,
      default: '',
      trim: true,
    },
    adminCode: {
      type: String,
      default: '',
      trim: true,
    },
    role: {
      type: String,
      enum: ['employee', 'manager'],
      required: true,
      default: 'employee',
    },
    resetPasswordToken: {
      type: String,
      default: '',
    },
    resetPasswordExpires: {
      type: Date,
    },
  },
  { timestamps: true },
)

module.exports = mongoose.model('User', UserSchema)

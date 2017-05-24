const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcrypt-nodejs')

// Define Model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
})

// On Save Hook, Encrypt Password
// Pre: Before saving run this function
userSchema.pre('save', function (next) {
  // Get access to user model
  const user = this

  // Generate salt, then run callback
  bcrypt.genSalt(10, function (err, salt) {
    if (err) { return next(err) }

    // Hash/encrypt password using salt
    bcrypt.hash(user.password, salt, null, function (err, hash) {
      if (err) { return next(err) }

      // Overwrite plain text password with encrypted password
      user.password = hash
      next()
    })
  })
})

userSchema.methods.comparePassword = function (candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) { return callback(err) }

    callback(null, isMatch)
  })
}

// Create Model Class
const modelClass = mongoose.model('user', userSchema)

// Export Model
module.exports = modelClass

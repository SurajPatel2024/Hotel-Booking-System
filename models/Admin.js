const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true }, // Enforce unique usernames
  password: { type: String, required: true },
});

module.exports = mongoose.model('Admin', adminSchema);


 
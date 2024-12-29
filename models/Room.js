const mongoose = require('mongoose'); // Import mongoose

const roomSchema = new mongoose.Schema({
    roomNumber: { type: Number, required: true, unique: true },
    type: { type: String, required: true },
    price: { type: Number, required: true },
    status: { type: String, required: true, default: 'Available' },
    description: { type: String, required: true },
    image: {
        data: Buffer,
        contentType: String,
    },
});

const Room = mongoose.model('Room', roomSchema);

module.exports = Room;

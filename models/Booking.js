const mongoose = require('mongoose');
 
const bookingSchema = new mongoose.Schema({
    room: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
    userName: { type: String, required: true },
    email:{type:String,require:true},
    userContact: { type: String, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    paymentStatus: { type: String, default: 'Paid' }, // 'Cash', 'Paid', or 'Pending'
  });
  
  const Booking = mongoose.model('Booking', bookingSchema);
  
module.exports = Booking;

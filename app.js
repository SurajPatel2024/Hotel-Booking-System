require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const Admin = require('./models/Admin');
const Room = require('./models/Room');
const Booking = require('./models/Booking');
const paypal = require('@paypal/checkout-server-sdk');
 
 
const app = express();
 
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key'; // Use environment variable for security

// MongoDB connection
mongoose.connect(process.env.DATABASE_URL,  {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected'); 
}).catch((err) => {
  console.error('MongoDB connection error:', err);
}); 

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Use memory storage for multer
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const fileTypes = /jpeg|jpg|png|gif/;
    const extname = fileTypes.test(file.originalname.toLowerCase());
    const mimeType = fileTypes.test(file.mimetype);

    if (mimeType && extname) {
      return cb(null, true);
    } else {
      cb('Error: Images only!');
    }
  },
});

// Middleware to verify JWT token
const isLoggedIn = (req, res, next) => {
  const token = req.cookies.jwtToken; // Retrieve token from cookies
  if (!token) return res.redirect('/admin/login')

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// User schema and model
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    match: [/^[A-Za-z]+$/, 'Username must contain only characters']
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[^@\s]+@[^@\s]+\.com$/, 'Email must end with .com']
  },
  password: {
    type: String,
    required: true,
  },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

 

// GET /signup
app.get('/signup', (req, res) => {
  res.render('signup', { message: '', messageType: '' });
});

// POST /signup
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Validate username (only alphabetic characters)
    const usernameRegex = /^[A-Za-z]+$/;
    if (!usernameRegex.test(username)) {
      return res.render('signup', {
        message: 'Username should only contain alphabetic characters!',
        messageType: 'error'
      });
    }

    // Validate email format
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    if (!emailRegex.test(email)) {
      return res.render('signup', {
        message: 'Please enter a valid email address!',
        messageType: 'error'
      });
    }

    // Check if the email or username already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.render('signup', {
        message: 'Email or Username already exists!',
        messageType: 'error'
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save new user
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.render('login', {
      message: 'Signup successful! Please log in.',
      messageType: 'success'
    });
  } catch (error) {
   
    res.render('signup', {
      message: 'An error occurred during signup. Please try again.',
      messageType: 'error'
    });
  }
});
 
// GET /login
app.get('/login', (req, res) => {
  res.render('login', { message: '', messageType: '' });
});

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.render('login', {
        message: 'Invalid username or password!',
        messageType: 'error'
      });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render('login', {
        message: 'Invalid username or password!',
        messageType: 'error'
      });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    // Set token in cookies
    res.cookie('authToken', token, { httpOnly: true });

    res.redirect('/UserHome'); // Redirect to a protected route
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', {
      message: 'An error occurred during login. Please try again.',
      messageType: 'error'
    });
  }
});



//reset password
app.get('/forgot', (req, res) => {
  res.render('forgot',{ 
      message: '',
      messageType: ''  
  })
  
});
app.post('/forgot', async(req, res) => {
  const { username, newPassword , email } = req.body;

  try {
      // Find the user by name and school
      const user = await User.findOne({username, email });
      if (!user) {
          return res.render('forgot',{
              message: 'Username or Email is wrong?',
              messageType: 'error'  
          })
         
      }

      // Hash the new password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      // Update the user's password
      user.password = hashedPassword;
      await user.save();
      res.render('login', {
          message: 'Password has been successfully updated. Please log in with your new password.',
          messageType: 'success' // Specify the type of the message
      });
      
       
  } catch (error) {
      console.error('Error in forget route:', error);
      res.send('An error occurred. Please try again later.');
  }
});

// Authentication middleware
const auth = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.redirect('/login');

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Invalid token:', err);
      return res.redirect('/login');
    }
    req.userId = decoded.userId; // Save userId for future use
    next();
  });
}; 

// Example protected route
app.get('/UserHome', auth, async (req, res) => {
  try {
    // Fetch the user's data using the userId stored in the JWT
    const user = await User.findById(req.userId);

    // Fetch the rooms data
    const rooms = await Room.find();

    // Render the page and pass the user data along with the rooms
    res.render('index', { message:'',messageType:'',
      rooms,
      user: {
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error fetching user or rooms data:', error);
    res.redirect('/login');
  }
});


app.get('/edit-profile', auth, async (req, res) => {
  try {
      // Retrieve user data using the ID from authentication middleware
      const user = await User.findById(req.userId); // Assuming req.userId is set
      if (!user) {
          return res.status(404).send('User not found');
      }

      // Render the edit-profile page with user details
      res.render('edit-profile', {
          user, // Pass the fetched user to the template
      });
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});
app.post('/edit-profile', auth, async (req, res) => {
  const { username, email } = req.body;

  // Validate required fields
  if (!username || !email) {
      return res.status(400).send('Username and email are required');
  }

  try {
      // Update the user details
      const updatedUser = await User.findByIdAndUpdate(
          req.userId, // Ensure this is set by auth middleware
          { username, email }, // Fields to update
          { new: true, runValidators: true } // Return updated user, validate fields
      );

      if (!updatedUser) {
          return res.status(404).send('User not found');
      }

      // Redirect to the profile page after a successful update
      res.redirect('/edit-profile');
  } catch (err) {
      console.error(err);
      res.status(500).send('Error updating profile');
  }
});
 






// Home Page
app.get('/', async (req, res) => {
  try {
    const rooms = await Room.find();
    res.render('index', { rooms, user: '' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching rooms');
  }
});
app.get('/logout', async (req, res) => {
 
    res.cookie('authToken','');
    res.redirect('/')
});

 
// Admin Login Form
app.get('/admin/login', (req, res) => {
  res.render('admin/login', {
    message: ' ',
    messageType: ' '
  });
  
});

// Admin Login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the admin by username
    const admin = await Admin.findOne({ username });

    // Check if admin exists and the password is correct
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.render('admin/login', {
        message: 'Invalid username or password!',
        messageType: 'error',
      });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: admin._id, username: admin.username }, JWT_SECRET, {
      expiresIn: '1h',
    });

    // Set token in cookies
    res.cookie('jwtToken', token, { httpOnly: true, maxAge: 3600000 });
    const rooms = await Room.find();
    const bookings = await Booking.find();
    if(username=="Suraj"){
      let a = 'Suraj'
      res.render('admin/dashboard', { rooms, bookings,a});
    }else{
      let a = null;
      res.render('admin/dashboard', { rooms, bookings, a: a });

    }
     // Fetch one admin
    
  } catch (err) {
    console.error('Error during login:', err);
    res.render('admin/login', {
      message: 'An error occurred during login.',
      messageType: 'error',
    });
  }
});


// Admin Register Form
app.get('/admin/register', (req, res) => {
  res.render('admin/register',{ message: ' ',
    messageType: ' '});
});

// Admin Register
app.post('/admin/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists
    const existingAdmin = await Admin.findOne({ username });
    if (existingAdmin) {
      return res.render('admin/register', {
        message: 'Username already exists. Please choose another.',
        messageType: 'error',
      });
    }

    // Hash the password manually
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the admin
    const admin = new Admin({ username, password: hashedPassword });
    await admin.save();

    res.render('admin/register', {
      message: 'Admin registered successfully!',
      messageType: 'success',
    });
  } catch (err) {
    console.error('Error registering admin:', err);
    res.render('admin/register', {
      message: 'Error registering admin.',
      messageType: 'error',
    });
  }
});



// Admin Dashboard
app.get('/admin/dashboard', isLoggedIn, async (req, res) => {
  try {
    const rooms = await Room.find();
    const bookings = await Booking.find();
     // Fetch one admin
     let a = null;
     res.render('admin/dashboard', { rooms, bookings, a: a });
     
    
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching data'); 
  }
});
app.get('/viewalladmin', isLoggedIn, async (req, res) => {
  try { 
 
    const admin = await Admin.find();
    res.render('admin/viewalladmin', {  admins: admin  });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching data'); 
  }
}); 
app.post('/viewadmin/delete/:id', async (req, res) => {
  try { 
    await Admin.findByIdAndDelete(req.params.id);
    res.redirect('/viewalladmin');
  } catch (err) {
    console.log(err);
  }
});

 

// Add New Room
app.get('/admin/rooms/new', isLoggedIn, (req, res) => {
  res.render('admin/new-room');
});

app.post('/admin/rooms/new', isLoggedIn, upload.single('image'), async (req, res) => {
  const { roomNumber, type, price, status, description } = req.body;
  const image = req.file;

  try {
    const newRoom = new Room({
      roomNumber,
      type,
      price,
      status,
      description,
      image: image
        ? {
            data: image.buffer,
            contentType: image.mimetype,
          }
        : null,
    });

    await newRoom.save();
    res.redirect('/admin/dashboard');
  } catch (err) {
    res.status(500).send('Error adding room: ' + err.message);
  }
});

// Edit Room
app.get('/admin/rooms/edit/:id', isLoggedIn, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    res.render('admin/edit-room', { room });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching room');
  }
});

app.post('/admin/rooms/edit/:id', isLoggedIn, upload.single('image'), async (req, res) => {
  try {
    const { roomNumber, type, price, description, status } = req.body;
    const room = await Room.findById(req.params.id);

    room.roomNumber = roomNumber;
    room.type = type;
    room.price = price;
    room.description = description;
    room.status = status;

    if (req.file) {
      room.image = {
        data: req.file.buffer,
        contentType: req.file.mimetype,
      };
    }

    await room.save();
    res.redirect('/admin/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating room');
  }
});

// Delete Room
app.get('/admin/rooms/delete/:id', isLoggedIn, async (req, res) => {
  try {
    await Room.findByIdAndDelete(req.params.id);
    res.redirect('/admin/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting room');
  }
});
 
// Only for admin View Bookings
app.get('/view-bookings', isLoggedIn, async (req, res) => {
  try {
    const bookings = await Booking.find().populate('room'); // Populate room details
    res.render('view-bookings', { bookings });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).send('Internal Server Error');
  }
});


 


// Admin View Bookings
app.get('/admin/bookings', isLoggedIn, async (req, res) => {
  try {
    const bookings = await Booking.find().populate('room');
    res.render('admin/view-bookings', { bookings });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Edit Booking
app.get('/admin/bookings/edit/:id', isLoggedIn, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id).populate('room');
    res.render('admin/edit-booking', { booking });
  } catch (error) {
    console.error('Error fetching booking:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/admin/bookings/edit/:id', isLoggedIn, async (req, res) => {
  const { roomNumber, userName, email, userContact, startDate, endDate, paymentStatus, paymentMethod } = req.body;

  try {
    const updatedBooking = await Booking.findByIdAndUpdate(
      req.params.id,
      {
        roomNumber,
        userName,
        email,
        userContact,
        startDate,
        endDate,
        paymentStatus,  // Updated manually by admin
        paymentMethod
      },
      { new: true }  // Return the updated booking
    );
    res.redirect('/view-bookings');  // Redirect after successful update
  } catch (error) {
    console.error('Error updating booking:', error);
    res.status(500).send('Internal Server Error');
  }
}); 

 // In your admin routes
app.get('/admin/bookings/details/:id', async (req, res) => {
  try {
      const booking = await Booking.findById(req.params.id).populate('room');
      if (!booking) {
          return res.status(404).send('Booking not found');
      }
      res.render('bookingDetails', { booking });
  } catch (err) {
      console.error(err);
      res.status(500).send('Error retrieving booking details');
  }
});
   
app.get('/admin/bookings/delete/:id', isLoggedIn, async (req, res) => {
  try {
    await Booking.findByIdAndDelete(req.params.id);
    res.redirect('/view-bookings');
  } catch (error) {
    console.error('Error deleting booking:', error);
    res.status(500).send('Internal Server Error');
  }
});

 // Logout
app.get('/admin/logout', (req, res) => {
  res.cookie('jwtToken','')
  res.redirect('/admin/login')
});

  

 
// Book Room Route
app.get('/book-room/:id', auth,async (req, res) => {
  try {
    
    const roomId = req.params.id;
    const room = await Room.findById(roomId);
    const user = await User.findById(req.userId);


    if (!room) {
      return res.status(404).send('Room not found');
    }
   
    res.render('book-room', { room , user: {
      username: user.username,
      email: user.email
    },message:" ",messageType:" "});
  } catch (error) {
    console.error('Error fetching room:', error);
    res.status(500).send('Internal Server Error'); 
  }
}); 
const session = require('express-session');
const MongoStore = require('connect-mongo');
 
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Make sure this is set correctly if you're using HTTPS
}));


   
const captchapng = require('captchapng');

app.get('/captcha', (req, res) => {
    const code = Math.floor(Math.random() * 9000) + 1000; // Generate a 4-digit code
    req.session.captcha = code; // Store CAPTCHA in session

    const p = new captchapng(80, 30, code); // CAPTCHA image dimensions and code
    p.color(0, 0, 0, 0); // Background color (black)
    p.color(0, 255, 0, 255); // Text color (green)

    const img = p.getBase64(); // Get the CAPTCHA image as base64
    const imgbase64 = Buffer.from(img, 'base64'); // Convert to Buffer for sending as response

    res.type('png');
    res.send(imgbase64); // Send CAPTCHA as a PNG image
});

// CAPTCHA validation endpoint
app.post('/verify-captcha', (req, res) => {
  const userCaptcha = req.body.captcha; // Get the user's CAPTCHA input
 

  // Ensure both are strings (or numbers) for comparison
  if (userCaptcha.trim() === req.session.captcha.toString()) {
      res.json({ success: true });
  } else {
      res.json({ success: false });
  }
});


// PayPal payment route with CAPTCHA validation
app.post('/book-room/:roomId', async (req, res) => {
  const roomId = req.params.roomId;
  const { userName, email, userContact, startDate, endDate, paymentMethod, captcha } = req.body;
 
  try {
      // Retrieve CAPTCHA from session
      const sessionCaptcha = req.session.captcha;

      // Check if the CAPTCHA matches
      if (!sessionCaptcha || captcha != sessionCaptcha) {
          req.session.captcha = null; // Clear CAPTCHA after use

          const room = await Room.findById(roomId);
          const user = await User.findById(req.userId);

          if (!room) {
              return res.status(404).send("Room not found");
          }

          return res.render('book-room', {
              room,
              user: {
                  username: user.username,
                  email: user.email,
              },
              message: "Invalid CAPTCHA. Please try again.",
              messageType: "error",
          });
      }

      // Clear CAPTCHA after successful validation
      req.session.captcha = null;

      // Continue with booking logic
      const room = await Room.findById(roomId);
      if (!room) {
          return res.status(404).send("Room not found");
      }

      room.status = 'Booked';
      await room.save();

      const booking = new Booking({
          room: roomId,
          userName,
          email,
          userContact,
          startDate,
          endDate,
          paymentStatus: paymentMethod === 'Online' ? 'Online Paid' : 'Cash Pending',
          status: room.status,
      });

      await booking.save();

      res.redirect(`/thank-you/${booking._id}`);
  } catch (err) {
      console.error('Error booking room:', err);
      res.status(500).send("Internal Server Error");
  }
});
 

// PayPal execute payment
app.get('/payment/execute/:id', async (req, res) => {
  const bookingId = req.params.id;
  const booking = await Booking.findById(bookingId);
  const payerId = req.query.PayerID;
  const orderId = req.query.token;
  const paymentMethod = req.query.paymentMethod;  // New parameter to differentiate payment method

  if (!booking || (!payerId && !paymentMethod) || !orderId) {
      return res.status(400).send('Invalid payment details');
  }

  try {
      if (paymentMethod === 'cash') {
          // If the payment method is cash, set payment status to "Cash Pending"
          booking.paymentStatus = 'Cash Pending';
          await booking.save();
          res.redirect('/thank-you'); // Redirect to the thank-you page or booking confirmation page
      } else if (paymentMethod === 'online' && payerId && orderId) {
          // If the payment method is online, process the PayPal payment
          const request = new paypal.orders.OrdersCaptureRequest(orderId);
          request.requestBody({});
          const capture = await client().execute(request);

          if (capture.result.status === 'COMPLETED') {
              booking.paymentStatus = 'Paid';
              await booking.save();
              res.redirect('/thank-you'); // Redirect to the thank-you page or booking confirmation page
          } else {
              res.status(400).send('Payment failed');
          }
      } else {
          res.status(400).send('Invalid payment method');
      }
  } catch (error) {
      console.error('Error executing payment:', error);
      res.status(500).send('Payment execution failed');
  }
});

// Thank You page
app.get('/thank-you/:bookingId', async (req, res) => {
  try {
    const bookingId = req.params.bookingId;

    // Fetch the booking details using the bookingId
    const booking = await Booking.findById(bookingId).populate('room');  // Populate room details
    if (!booking) {
      return res.status(404).send('Booking not found');
    }

    // Render the thank-you page with booking details
    res.render('thank-you', { booking, room: booking.room });
  } catch (error) {
    console.error('Error fetching booking details:', error);
    res.status(500).send('Internal Server Error');
  }
});
 
// User Bookings Route
app.get('/user-bookings', auth, async (req, res) => {
  try {
    const userId = req.userId; // Get the userId from the request (ensure user is authenticated)
   // Get user bookings
    const bookings = await Booking.find().populate('room'); 

    // Render the user-bookings page, passing the user and booking data
    const user = await User.findById(userId).select('username email _id');
    res.render('user-bookings', { user, bookings });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).send('Internal Server Error');
  }
}); 











const Message = require('./models/Message');
app.post('/submit',auth, async (req, res) => {
  const { name, email, message } = req.body;

  // Create a new Message document
  const newMessage = new Message({
      name,
      email,
      message
  });

  try {
      // Save the message to the database
      await newMessage.save();
      const user = await User.findById(req.userId);

      // Fetch the rooms data
      const rooms = await Room.find();
  
      res.redirect('/UserHome')
  } catch (err) {
      console.error('Error saving message:', err);
      res.render('index');
  }
});

// Route to view saved messages (admin page)
app.get('/admin/messages',isLoggedIn, async (req, res) => {
  try {
      // Get all messages from the database
      const messages = await Message.find();

      // Render an admin page to display the messages 
      res.render('admin/adminMessages', { messages });
  } catch (err) {
      console.error('Error fetching messages:', err);
      res.render('adminMessages', { messages: [] });
  }
});
 // Delete message by ID
app.post('/admin/messages/:id', isLoggedIn, async (req, res) => {
  try {
    const messageId = req.params.id;

    // Find and delete the message from the database 
    await Message.findByIdAndDelete(messageId);

    // Redirect back to the messages page after deletion
    res.redirect('/admin/messages');
  } catch (err) {
    console.error('Error deleting message:', err);
    res.status(500).send('Server error');
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
  
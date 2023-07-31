const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/otp_auth';

mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});
mongoose.connection.on('error', (err) => {
  console.error('Error connecting to MongoDB:', err);
});

app.use(bodyParser.json());

// MongoDB Schema and Model for User
const userSchema = new mongoose.Schema({
  phoneNumber: { type: String, required: true },
  otp: { type: String, required: true },
  otpExpiration: { type: Date, required: true },
});

const User = mongoose.model('User', userSchema);

// Twilio Configuration
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Endpoint for User Registration
app.post('/register', async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    // Generate a random 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Set OTP expiration to 5 minutes from now
    const otpExpiration = new Date(Date.now() + 5 * 60 * 1000);

    // Save user data to MongoDB
    await User.create({ phoneNumber, otp, otpExpiration });

    // Send OTP via Twilio SMS
    await twilioClient.messages.create({
      body: `Your OTP for registration is: ${otp}`,
      to: phoneNumber,
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.status(200).json({ message: 'OTP sent successfully.' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ error: 'Failed to register user.' });
  }
});

// Endpoint for User Login with OTP
app.post('/login', async (req, res) => {
  try {
    const { phoneNumber, otp } = req.body;

    // Find the user in the database
    const user = await User.findOne({ phoneNumber });

    // Check if the OTP is valid and not expired
    if (!user || user.otp !== otp || user.otpExpiration < Date.now()) {
      return res.status(401).json({ error: 'Invalid OTP or OTP expired.' });
    }

    // Generate and send JWT token
    const token = jwt.sign({ phoneNumber: user.phoneNumber }, process.env.JWT_SECRET, {
      expiresIn: '1h', // Token expires in 1 hour
    });

    res.status(200).json({ token });
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ error: 'Failed to login.' });
  }
});

// Middleware to protect routes with JWT
function authenticateJWT(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });

    req.user = user;
    next();
  });
}

// Protected Route Example
app.get('/protected', authenticateJWT, (req, res) => {
  // This route is protected with JWT. The user object can be accessed with req.user.
  res.json({ message: 'Protected route accessed successfully.', user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import otpGenerator from 'otp-generator';
import { User } from './src/models/User.js';
const app = express();

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Store OTPs temporarily (in production, use Redis or similar)
const otpStore = new Map();

// Middleware
app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

connectDB();

// Define Donation Schema and Model
const donationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  donor: { type: String, required: true },
  contact: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  items: { type: String, required: true },
  location: { type: String, required: true },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'rejected'],
    default: 'pending',
  },
  notes: { type: String, default: '' }
}, { timestamps: true });

const Donation = mongoose.model('Donation', donationSchema);

// Auth Routes
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Generate OTP
    const otp = otpGenerator.generate(6, { 
      digits: true, 
      alphabets: false, 
      upperCase: false, 
      specialChars: false 
    });
    
    // Store OTP with 5 minutes expiry
    otpStore.set(email, {
      otp,
      expiry: Date.now() + 5 * 60 * 1000 // 5 minutes
    });
    
    // Send email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for ApparelCycle Hub',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>Welcome to ApparelCycle Hub!</h2>
          <p>Your OTP for verification is: <strong>${otp}</strong></p>
          <p>This OTP will expire in 5 minutes.</p>
        </div>
      `
    });
    
    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    const storedData = otpStore.get(email);
    if (!storedData) {
      return res.status(400).json({ message: 'OTP expired or not found' });
    }
    
    if (Date.now() > storedData.expiry) {
      otpStore.delete(email);
      return res.status(400).json({ message: 'OTP expired' });
    }
    
    if (otp !== storedData.otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }
    
    // OTP is valid, find or create user
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, name: email.split('@')[0] });
      await user.save();
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    // Clear OTP
    otpStore.delete(email);
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Failed to verify OTP' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    console.log('Registration attempt for:', email);
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }
    
    // Create new user (password will be hashed by the User model)
    console.log('Creating new user with email:', email);
    const user = new User({ name, email, password });
    await user.save();
    console.log('User created successfully:', email);
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Get authenticated user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt for email:', email);
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found:', email);
      return res.status(404).json({ message: 'User not found' });
    }
    console.log('User found:', user.email);
    
    // Check password using the User model's comparePassword method
    try {
      const isValidPassword = await user.comparePassword(password);
      console.log('Password comparison result:', isValidPassword);
      
      if (!isValidPassword) {
        console.log('Invalid password for user:', email);
        return res.status(401).json({ message: 'Invalid password' });
      }
    } catch (error) {
      console.error('Error comparing passwords:', error);
      return res.status(500).json({ message: 'Error validating password' });
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Protected API Routes
app.post('/api/donations', authenticateToken, async (req, res) => {
  try {
    const donation = new Donation({
      ...req.body,
      userId: req.user._id
    });
    await donation.save();
    res.status(201).json(donation);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/api/donations', authenticateToken, async (req, res) => {
  try {
    const { status } = req.query;
    let query = { userId: req.user._id };
    
    if (status === 'active') {
      query = { status: { $in: ['pending', 'confirmed'] } };
    } else if (status) {
      query = { status };
    }
    
    const donations = await Donation.find(query).sort({ createdAt: -1 });
    res.json(donations);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/donations/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const donation = await Donation.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    
    if (!donation) {
      return res.status(404).json({ message: 'Donation not found' });
    }
    
    res.json(donation);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/donations/report', async (req, res) => {
  try {
    const donations = await Donation.find().sort({ createdAt: -1 });
    
    // Generate CSV string
    let csv = 'ID,Donor,Contact,Date,Time,Items,Location,Status,Notes\n';
    
    donations.forEach(donation => {
      csv += `${donation._id},${donation.donor},${donation.contact},${donation.date},${donation.time},"${donation.items}","${donation.location}",${donation.status},"${donation.notes}"\n`;
    });
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=donations-${Date.now()}.csv`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Server setup
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

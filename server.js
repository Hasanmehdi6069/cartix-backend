require('dotenv').config(); // 1. ENVIRONMENT VARIABLES FIRST
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const session = require('express-session'); // Google Auth
const passport = require('passport'); // Google Auth
const GoogleStrategy = require('passport-google-oauth20').Strategy; // Google Auth

const app = express(); // 2. INITIALIZE THE APP

// =========================================================
// 3. MIDDLEWARE ENGINE (Must be before routes!)
// =========================================================
app.use(cors()); 
app.use(express.json()); 

// 🔐 QART SECURITY & SESSION ENGINE (Google Auth)
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_if_env_fails',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true later when deploying with HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

// Tell Passport how to save the user to the session
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// =======================================================
// 🌍 GOOGLE OAUTH 2.0 STRATEGY
// =======================================================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // 🔴 CHANGED TO YOUR LIVE RENDER BACKEND
    callbackURL: "https://cartix-api.onrender.com/api/auth/google/callback" 
  },
    async (accessToken, refreshToken, profile, done) => {
        try {
            // Check if user already exists in DB
            let user = await User.findOne({ email: profile.emails[0].value });
            if (!user) {
                // If not, create a new user (No password needed for Google users!)
                user = new User({
                    fullName: profile.displayName,
                    email: profile.emails[0].value,
                    password: null
                });
                await user.save();
                console.log("✅ NEW GOOGLE USER CREATED:", profile.emails[0].value);
            } else {
                console.log("🔓 GOOGLE USER LOGGED IN:", profile.emails[0].value);
            }
            return done(null, user);
        } catch (error) {
            return done(error, null);
        }
    }
));

// =========================================================
// 4. MONGODB CONNECTION
// =========================================================
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('🔥 MONGODB CONNECTED SECURELY! Qart DB is LIVE.'))
    .catch(err => console.error('🔴 MONGODB CONNECTION FAILED:', err));

// =========================================================
// 5. DATABASE SCHEMAS
// =========================================================
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: false } // Required is false because Google users won't have a password!
});
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    shippingAddress: { type: String, required: true },
    items: { type: Array, required: true }, 
    totalAmount: { type: Number, required: true },
    status: { type: String, default: 'Processing' }, 
    orderDate: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// =========================================================
// 6. TRADITIONAL AUTH ROUTES (Signup / Login)
// =========================================================
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists!" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ fullName, email, password: hashedPassword });
        await newUser.save();
        
        console.log("✅ SECURE USER SAVED:", email);
        res.status(201).json({ message: "Signup Successful!", user: { fullName } });
    } catch (error) {
        res.status(500).json({ message: "Server Error", error });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(401).json({ message: "Invalid email or password!" });

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            console.log("🔓 USER LOGGED IN SECURELY:", email);
            res.json({ message: "Login successful!", user: { fullName: user.fullName } });
        } else {
            res.status(401).json({ message: "Invalid email or password!" });
        }
    } catch (error) {
        res.status(500).json({ message: "Server Error", error });
    }
});

// =======================================================
// 🚀 GOOGLE AUTHENTICATION ROUTES
// =======================================================

// 1. Send the user to Google (Forces Account Selection!)
app.get('/auth/google',
  passport.authenticate('google', { 
      scope: ['profile', 'email'],
      prompt: 'select_account' 
  })
);

// 2. Catch the user when Google sends them back!
app.get('/api/auth/google/callback',
  // 🔴 CHANGE 1: Update the failure redirect to your NEW domain
  passport.authenticate('google', { failureRedirect: 'https://cartixthewhole.netlify.app/Login.html' }), 
  (req, res) => {
    // 🔴 CHANGE 2: Added a fallback in case Google doesn't send a display name
    const userName = encodeURIComponent(req.user.displayName || 'VIP User');
    
    // 🔴 CHANGE 3: Redirect to your NEW domain
    res.redirect(`https://cartixthewhole.netlify.app/Index.html?login=success&name=${userName}`);
  }
);

// =========================================================
// 7. ORDER MANAGEMENT ROUTES
// =========================================================
app.post('/api/orders', async (req, res) => {
    try {
        const { customerName, shippingAddress, items, totalAmount } = req.body;
        const newOrder = new Order({ customerName, shippingAddress, items, totalAmount });
        await newOrder.save();
        
        console.log("📦 NEW ORDER RECEIVED AND SAVED! Order ID:", newOrder._id);
        res.status(201).json({ message: "Order placed successfully!", orderId: newOrder._id });
    } catch (error) {
        res.status(500).json({ message: "Server Error: Could not place order.", error });
    }
});

app.get('/api/orders/:customerName', async (req, res) => {
    try {
        const userOrders = await Order.find({ customerName: req.params.customerName }).sort({ orderDate: -1 });
        res.json(userOrders);
    } catch (error) {
        res.status(500).json({ message: "Server Error", error });
    }
});

app.get('/api/status', (req, res) => {
    res.json({ message: "Qart Backend is fully operational." });
});

// =========================================================
// 8. BOOT UP THE SERVER (Must be at the very bottom!)
// =========================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 SERVER RUNNING ON PORT ${PORT}`));
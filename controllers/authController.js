const admin = require('../config/firebase');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const NodeCache = require('node-cache');
const tokenCache = new NodeCache({ stdTTL: 300 });

// Function to generate a 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Function to validate if the email is from the acredge.in domain
const validateEmail = (email) => {
  const regex = /@acredge\.in$/;
  return regex.test(email);
};

// Function to send an OTP to the user's email using Nodemailer
const sendEmail = async (to, otp) => {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_APP_PASSWORD
    }
  });

  let info = await transporter.sendMail({
    from: '"Admin Login" <sandeephunter2002@gmail.com>',
    to: to,
    subject: "Your OTP for Admin Login",
    text: `Your OTP is: ${otp}`,
    html: `<b>Your OTP is: ${otp}</b>`
  });

  console.log("Message sent: %s", info.messageId);
};

// Controller function to verify the email and send an OTP
exports.verifyEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Email doesn't match the required format." });
    }

    const otp = generateOTP();
    const expirationTime = Date.now() + 300000; // OTP is valid for 5 minutes

    await admin.firestore().collection('otps').doc(email).set({
      otp,
      expirationTime,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await sendEmail(email, otp);

    res.status(200).json({ message: "Verified successfully. OTP sent to email." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Login error occurred." });
  }
};

// Controller function to verify the OTP and log the user in
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp, rememberMe } = req.body;

    const otpDoc = await admin.firestore().collection('otps').doc(email).get();
    if (!otpDoc.exists || otpDoc.data().otp !== otp) {
      return res.status(400).json({ message: "Invalid or expired OTP." });
    }

    await admin.firestore().collection('otps').doc(email).delete();

    const expiresIn = rememberMe ? '7d' : '24h';
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn });

    // Store the token in Firestore
    await admin.firestore().collection('tokens').doc(email).set({
      token,
      expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + (rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)))
    });

    // Set the cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      path: '/'  // Ensure the cookie is accessible for all paths
    });

    console.log('Cookie set:', token); // Log for debugging

    res.status(200).json({ message: "Logged in successfully" });
  } catch (error) {
    console.error('Error in verifyOTP:', error);
    res.status(500).json({ message: "OTP error occurred." });
  }
};

exports.isAuthenticated = async (req, res, next) => {
  try {
    console.log('Cookies received:', req.cookies);
    const token = req.cookies.token;
    console.log('Token extracted:', token);

    if (!token) {
      console.log('No token provided in cookies');
      return res.status(401).json({ message: "No token provided." });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Token decoded successfully:', decoded);
    } catch (error) {
      console.log('Token verification failed:', error.message);
      return res.status(401).json({ message: "Invalid token." });
    }
    
    // Check if the token is in the cache
    const cachedToken = tokenCache.get(decoded.email);
    if (cachedToken === token) {
      console.log('Token found in cache');
      req.user = decoded;
      return next();
    }

    console.log('Token not in cache, checking Firestore');
    // If not in cache, check Firestore
    const tokenDoc = await admin.firestore().collection('tokens').doc(decoded.email).get();

    if (!tokenDoc.exists) {
      console.log('Token document not found in Firestore');
      return res.status(401).json({ message: "Invalid token." });
    }

    if (tokenDoc.data().token !== token) {
      console.log('Token in Firestore does not match provided token');
      return res.status(401).json({ message: "Invalid token." });
    }

    if (tokenDoc.data().expiresAt.toDate() < new Date()) {
      console.log('Token has expired');
      await admin.firestore().collection('tokens').doc(decoded.email).delete();
      return res.status(401).json({ message: "Token has expired." });
    }

    // Cache the valid token
    tokenCache.set(decoded.email, token);
    console.log('Token cached');

    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error in isAuthenticated:', error);
    res.status(401).json({ message: "Authentication failed." });
  }
};

exports.logout = async (req, res) => {
  try {
    console.log('Request cookies:', req.cookies);
    console.log('Request headers:', req.headers);
    const token = req.cookies.token;
    console.log('Token from cookies:', token);
    
    if (!token) {
      console.log('No token found in cookies');
      return res.status(401).json({ message: "No token provided." });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      await admin.firestore().collection('tokens').doc(decoded.email).delete();
    } catch (jwtError) {
      console.error('JWT verification failed:', jwtError);
      return res.status(401).json({ message: "Invalid token." });
    }

    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/' // patsas
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: "Logout error occurred." });
  }
};

exports.checkAuth = async (req, res) => {
  res.status(200).json({ message: "Authenticated", user: req.user });
};
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
    console.log('Entering verifyOTP function');
    const { email, otp, rememberMe } = req.body;
    console.log(`Received OTP verification request for email: ${email}, rememberMe: ${rememberMe}`);

    const otpDoc = await admin.firestore().collection('otps').doc(email).get();
    if (!otpDoc.exists || otpDoc.data().otp !== otp) {
      console.log(`Invalid or expired OTP for email: ${email}`);
      return res.status(400).json({ message: "Invalid or expired OTP." });
    }

    console.log(`Valid OTP provided for email: ${email}`);
    await admin.firestore().collection('otps').doc(email).delete();
    console.log(`Deleted OTP document for email: ${email}`);

    const expiresIn = rememberMe ? '7d' : '24h';
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn });
    console.log(`Generated JWT token for email: ${email}, expiresIn: ${expiresIn}`);

    // Store the token in Firestore
    const expirationDate = new Date(Date.now() + (rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000));
    await admin.firestore().collection('tokens').doc(email).set({
      token,
      expiresAt: admin.firestore.Timestamp.fromDate(expirationDate)
    });
    console.log(`Stored token in Firestore for email: ${email}, expires at: ${expirationDate}`);

    // Set the cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
    });
    console.log(`Set cookie for email: ${email}, token: ${token.substring(0, 20)}...`);

    console.log(`Login successful for email: ${email}`);
    res.status(200).json({ message: "Logged in successfully" });
  } catch (error) {
    console.error('Error in verifyOTP:', error);
    res.status(500).json({ message: "OTP error occurred." });
  }
};

exports.isAuthenticated = async (req, res, next) => {
  try {
    console.log('Entering isAuthenticated middleware');
    const token = req.cookies.token;

    if (!token) {
      console.log('No token provided in cookies');
      return res.status(401).json({ message: "No token provided." });
    }

    console.log(`Token found in cookies: ${token.substring(0, 20)}...`);

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log(`Token verified successfully for email: ${decoded.email}`);
    } catch (error) {
      console.log('Token verification failed:', error.message);
      return res.status(401).json({ message: "Invalid token." });
    }
    
    // Check if the token is in the cache
    const cachedToken = tokenCache.get(decoded.email);
    if (cachedToken === token) {
      console.log(`Token found in cache for email: ${decoded.email}`);
      req.user = decoded;
      return next();
    }

    console.log(`Token not in cache, checking Firestore for email: ${decoded.email}`);
    // If not in cache, check Firestore
    const tokenDoc = await admin.firestore().collection('tokens').doc(decoded.email).get();

    if (!tokenDoc.exists || tokenDoc.data().token !== token || tokenDoc.data().expiresAt.toDate() < new Date()) {
      console.log(`Invalid or expired token in Firestore for email: ${decoded.email}`);
      return res.status(401).json({ message: "Invalid or expired token." });
    }

    // Cache the valid token
    tokenCache.set(decoded.email, token);
    console.log(`Token cached for email: ${decoded.email}`);

    req.user = decoded;
    console.log(`User authenticated: ${decoded.email}`);
    next();
  } catch (error) {
    console.error('Error in isAuthenticated:', error);
    res.status(401).json({ message: "Authentication failed." });
  }
};

exports.logout = async (req, res) => {
  try {
    console.log('Entering logout function');
    const token = req.cookies.token;
    
    if (!token) {
      console.log('No token found in cookies during logout');
      return res.status(401).json({ message: "Already Logged Out, Please login again to continue." });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log(`Token verified for logout, email: ${decoded.email}`);
      await admin.firestore().collection('tokens').doc(decoded.email).delete();
      console.log(`Deleted token from Firestore for email: ${decoded.email}`);
      tokenCache.del(decoded.email);
      console.log(`Removed token from cache for email: ${decoded.email}`);
    } catch (jwtError) {
      console.error('JWT verification failed during logout:', jwtError);
    }

    res.clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });
    console.log('Cleared token cookie');

    console.log('Logout successful');
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: "Logout error occurred." });
  }
};

exports.checkAuth = async (req, res) => {
  console.log(`CheckAuth called, user: ${req.user.email}`);
  res.status(200).json({ message: "Authenticated", user: req.user });
};
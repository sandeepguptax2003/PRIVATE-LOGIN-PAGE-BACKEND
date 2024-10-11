const admin = require('../config/firebase');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

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

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    });

    res.status(200).json({ message: "Logged in successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "OTP error occurred." });
  }
};

exports.isAuthenticated = async (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: "No token provided." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if the token exists in Firestore
    const tokenDoc = await admin.firestore().collection('tokens').doc(decoded.email).get();

    if (!tokenDoc.exists || tokenDoc.data().token !== token) {
      return res.status(401).json({ message: "Invalid token." });
    }

    if (tokenDoc.data().expiresAt.toDate() < new Date()) {
      await admin.firestore().collection('tokens').doc(decoded.email).delete();
      return res.status(401).json({ message: "Token has expired." });
    }

    req.user = decoded;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ message: "Authentication failed." });
  }
};

exports.logout = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      await admin.firestore().collection('tokens').doc(decoded.email).delete();
    }
    res.clearCookie('token');
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Logout error occurred." });
  }
};

exports.checkAuth = async (req, res) => {
  res.status(200).json({ message: "Authenticated", user: req.user });
};
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');

const app = express();

// CORS configuration
const corsOptions = {
  origin: 'https://wisdompeak-assignment.web.app', // Your frontend domain
  credentials: true, // This is important for cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'] // Allowed headers
};

app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(cookieParser());

// Routes for any requests starting with '/api/auth'
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
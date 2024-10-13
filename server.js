require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');

const app = express();

// CORS configuration
// const corsOptions = {
//   origin: ['https://wisdompeak-assignment.web.app', ''], // Allowed frontend domains
//   credentials: true, // Important for cookies
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'] // Allowed headers
// };

// // Handle preflight requests
// app.options('*', cors(corsOptions)); 

// app.use(cors(corsOptions));

app.use(cors({
  origin: true, // Or specify your frontend domain
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
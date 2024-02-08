const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");

const app = express();
const port = 3000;

// Apply security middleware
app.use(helmet());
app.use(cors());

// Apply rate limiting middleware to prevent abuse
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later",
});
app.use(limiter);

// Example IP blocking middleware
const blockedIPs = new Set();
const requestCounts = new Map();

function blockIP(req, res, next) {
  const clientIP = req.ip;
  if (blockedIPs.has(clientIP)) {
    res.status(403).send("Access forbidden");
  } else {
    next();
  }
}

// Apply IP blocking middleware to specific routes
app.get("/api/resource", blockIP, (req, res) => {
  res.json({ message: "This is a protected API resource" });
});

// Middleware to track request counts per IP and block IPs with too many requests
app.use((req, res, next) => {
  const clientIP = req.ip;
  const requestCount = requestCounts.get(clientIP) || 0;
  if (requestCount >= 100) {
    // Adjust the threshold as needed
    blockedIPs.add(clientIP);
    console.log(`Blocked IP address: ${clientIP}`);
  } else {
    requestCounts.set(clientIP, requestCount + 1);
  }
  next();
});

// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});

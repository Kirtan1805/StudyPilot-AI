
require("dotenv").config();

const jwt = require("jsonwebtoken");

const token = process.env.TEST_JWT;

if (!token) {
  console.error("Usage: node src/config/test-jwt.js <token>");
  process.exit(1);
}

try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    issuer: "studypilot-auth"
  });

  console.log("JWT verified successfully!");
  console.log("Subject (user ID):", decoded.sub);
  console.log("Email:", decoded.email);
  console.log("Issuer:", decoded.iss);
  console.log("Issued at:", new Date(decoded.iat * 1000).toISOString());
  console.log("Expires at:", new Date(decoded.exp * 1000).toISOString());
} catch (error) {
  console.error("JWT verification failed:", error.message);
  process.exitCode = 1;
}

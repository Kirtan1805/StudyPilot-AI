
const bcrypt = require("bcrypt");
const pool = require("../config/db");
const jwt = require("jsonwebtoken");

async function registerUser(email, password) {
  const normalizedEmail = email.trim().toLowerCase();

  // Check whether this email is already registered.
  const existingUser = await pool.query(
    "SELECT id FROM users WHERE LOWER(email) = $1",
    [normalizedEmail]
  );

  if (existingUser.rows.length > 0) {
    const error = new Error("Email is already registered");
    error.statusCode = 409;
    throw error;
  }

  // Hash the password before storing it.
  const passwordHash = await bcrypt.hash(password, 12);

  // Insert the new user safely.
  const result = await pool.query(
    `INSERT INTO users (email, password_hash)
     VALUES ($1, $2)
     RETURNING id, email, email_verified, created_at`,
    [normalizedEmail, passwordHash]
  );

  return result.rows[0];
}

// Add this function alongside your existing registerUser function.
async function loginUser(email, password) {
  const normalizedEmail = email.trim().toLowerCase();

  const result = await pool.query(
    `SELECT id, email, password_hash, email_verified
     FROM users
     WHERE LOWER(email) = $1`,
    [normalizedEmail]
  );

  const user = result.rows[0];

  // Use the same error for unknown email and incorrect password.
  if (!user) {
    const error = new Error("Invalid email or password");
    error.statusCode = 401;
    throw error;
  }

  const passwordMatches = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!passwordMatches) {
    const error = new Error("Invalid email or password");
    error.statusCode = 401;
    throw error;
  }

  const accessToken = jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "15m",
      issuer: "studypilot-auth"
    }
  );

  return {
    user: {
      id: user.id,
      email: user.email,
      email_verified: user.email_verified
    },
    accessToken
  };
}

module.exports = {
  registerUser,
  loginUser
};

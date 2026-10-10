
const bcrypt = require("bcrypt");
const pool = require("../config/db");

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

module.exports = { registerUser };

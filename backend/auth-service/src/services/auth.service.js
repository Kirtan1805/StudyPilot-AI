
const bcrypt = require("bcrypt");
const pool = require("../config/db");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

function generateRefreshToken() {
  return crypto.randomBytes(64).toString("hex");
}
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
  // Generate a refresh token.
const refreshToken = generateRefreshToken();

// Store only its SHA-256 hash in PostgreSQL.
const refreshTokenHash = crypto
  .createHash("sha256")
  .update(refreshToken)
  .digest("hex");

// Set the session expiration to 7 days.
const expiresAt = new Date(
  Date.now() + 7 * 24 * 60 * 60 * 1000
);

await pool.query(
  `INSERT INTO sessions (user_id, refresh_token_hash, expires_at)
   VALUES ($1, $2, $3)`,
  [user.id, refreshTokenHash, expiresAt]
);

  
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
    accessToken,
     refreshToken
  };
}


async function refreshAccessToken(refreshToken) {
  if (
    typeof refreshToken !== "string" ||
    !/^[a-f0-9]{128}$/i.test(refreshToken)
  ) {
    const error = new Error("Invalid refresh token");
    error.statusCode = 401;
    throw error;
  }

  const client = await pool.connect();
  let transactionStarted = false;

  try {
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await client.query("BEGIN");
    transactionStarted = true;

    // Lock the matching session to prevent concurrent reuse.
    const result = await client.query(
      `SELECT s.id, s.user_id, u.email
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.refresh_token_hash = $1
         AND s.expires_at > NOW()
         AND s.revoked_at IS NULL
       FOR UPDATE OF s`,
      [refreshTokenHash]
    );

    const session = result.rows[0];

    if (!session) {
      const error = new Error("Invalid or expired refresh token");
      error.statusCode = 401;
      throw error;
    }

    // Generate replacement refresh token.
    const newRefreshToken = generateRefreshToken();

    const newRefreshTokenHash = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    );

    // Revoke the old session.
    await client.query(
      `UPDATE sessions
       SET revoked_at = NOW()
       WHERE id = $1`,
      [session.id]
    );

    // Store only the replacement token hash.
    await client.query(
      `INSERT INTO sessions (user_id, refresh_token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [session.user_id, newRefreshTokenHash, expiresAt]
    );

    const accessToken = jwt.sign(
      {
        sub: session.user_id,
        email: session.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "15m",
        issuer: "studypilot-auth"
      }
    );

    await client.query("COMMIT");
    transactionStarted = false;

    return {
      accessToken,
      refreshToken: newRefreshToken
    };

  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error("Transaction rollback failed:", rollbackError.message);
      }
    }

    throw error;

  } finally {
    client.release();
  }
}



async function logoutUser(refreshToken) {
  if (
    typeof refreshToken !== "string" ||
    !/^[a-f0-9]{128}$/i.test(refreshToken)
  ) {
    const error = new Error("Invalid refresh token");
    error.statusCode = 401;
    throw error;
  }

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const result = await pool.query(
    `UPDATE sessions
     SET revoked_at = NOW()
     WHERE refresh_token_hash = $1
       AND revoked_at IS NULL
     RETURNING id`,
    [refreshTokenHash]
  );

  if (result.rowCount === 0) {
    const error = new Error("Invalid or already revoked refresh token");
    error.statusCode = 401;
    throw error;
  }

  return { success: true };
}

module.exports = {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser
};

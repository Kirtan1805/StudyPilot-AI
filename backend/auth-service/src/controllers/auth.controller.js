
const {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser
} = require("../services/auth.service");

const register = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields.
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        status: "error",
        message: "Email and password are required",
      });
    }

    // Basic email format validation.
    const normalizedEmail = email.trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({
        status: "error",
        message: "Please provide a valid email address",
      });
    }

    // bcrypt has a 72-byte password input limit.
    if (Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({
        status: "error",
        message: "Password must not exceed 72 bytes",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        status: "error",
        message: "Password must contain at least 8 characters",
      });
    }

    const user = await registerUser(email, password);

    return res.status(201).json({
      status: "success",
      message: "Account created successfully",
      user,
    });
  } catch (error) {
    if (error.statusCode === 409) {
      return res.status(409).json({
        status: "error",
        message: error.message,
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to create account",
    });
  }
};


const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        status: "error",
        message: "Email and password are required"
      });
    }

    const result = await loginUser(email, password);

    return res.status(200).json({
      status: "success",
      message: "Login successful",
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({
        status: "error",
        message: "Invalid email or password"
      });
    }

    console.error("Login error:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to log in"
    });
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (typeof refreshToken !== "string" || !refreshToken) {
      return res.status(400).json({
        status: "error",
        message: "Refresh token is required"
      });
    }

    const result = await refreshAccessToken(refreshToken);

    return res.status(200).json({
      status: "success",
      message: "Access token refreshed successfully",
      accessToken: result.accessToken
    });
  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({
        status: "error",
        message: "Invalid or expired refresh token"
      });
    }

    console.error("Token refresh error:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to refresh access token"
    });
  }
};

const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (typeof refreshToken !== "string" || !refreshToken) {
      return res.status(400).json({
        status: "error",
        message: "Refresh token is required"
      });
    }

    await logoutUser(refreshToken);

    return res.status(200).json({
      status: "success",
      message: "Logout successful"
    });
  } catch (error) {
    if (error.statusCode === 401) {
      return res.status(401).json({
        status: "error",
        message: error.message
      });
    }

    console.error("Logout error:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to log out"
    });
  }
};

module.exports = {
  register,
  login,
  refresh,
  logout
};

const { registerUser } = require("../services/auth.service");

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

module.exports = { register };

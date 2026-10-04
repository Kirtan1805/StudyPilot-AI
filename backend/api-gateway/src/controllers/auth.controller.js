const {
  getAuthHealth
} = require("../services/auth.service");

const authHealth = async (req, res) => {
  try {
    const result = await getAuthHealth();

    res.status(result.status).json(result.data);
  } catch (error) {
    console.error("Auth Service error:", error.message);

    res.status(503).json({
      status: "error",
      service: "auth-service",
      message: "Auth Service is unavailable"
    });
  }
};

module.exports = {
  authHealth
};

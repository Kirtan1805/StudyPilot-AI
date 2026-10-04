const express = require("express");

const router = express.Router();

router.get("/health", async (req, res) => {
  try {
    const response = await fetch(
      `${process.env.AUTH_SERVICE_URL}/health`
    );

    const data = await response.json();

    res.status(response.status).json(data);
  } catch (error) {
    console.error("Auth Service error:", error.message);

    res.status(503).json({
      status: "error",
      service: "auth-service",
      message: "Auth Service is unavailable"
    });
  }
});

module.exports = router;

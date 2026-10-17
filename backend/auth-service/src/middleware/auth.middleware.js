
const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  // Check whether the Authorization header exists.
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      status: "error",
      message: "Access token is required"
    });
  }

  // Extract the token after "Bearer ".
  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "studypilot-auth"
    });

    // Make the verified user's identity available to the endpoint.
    req.user = {
      id: decoded.sub,
      email: decoded.email
    };

    // Allow Express to continue to the next handler.
    next();
  } catch (error) {
    return res.status(401).json({
      status: "error",
      message: "Invalid or expired access token"
    });
  }
}

module.exports = { authenticateToken };

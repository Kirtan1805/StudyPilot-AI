
const express = require("express");
const { authenticateToken } = require("../middleware/auth.middleware");
const {
  register,
  login
} = require("../controllers/auth.controller");


const router = express.Router();

router.post("/register", register);
router.post("/login", login);

router.get("/protected-test", authenticateToken, (req, res) => {
  res.status(200).json({
    status: "success",
    message: "You accessed a protected endpoint!",
    user: req.user
  });
});

module.exports = router;

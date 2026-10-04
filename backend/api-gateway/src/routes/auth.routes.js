const express = require("express");

const {
  authHealth
} = require("../controllers/auth.controller");

const router = express.Router();

router.get("/health", authHealth);

module.exports = router;

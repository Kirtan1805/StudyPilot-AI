const express = require("express");

const healthRoutes = require("./routes/health.routes");
const authRoutes = require("./routes/auth.routes");

const app = express();

app.use(express.json());

app.use("/", healthRoutes);
app.use("/", authRoutes);

module.exports = app;

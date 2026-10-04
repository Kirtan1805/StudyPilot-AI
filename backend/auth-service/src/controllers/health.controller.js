const getHealth = (req, res) => {
  res.json({
    status: "ok",
    service: "auth-service"
  });
};

module.exports = {
  getHealth
};

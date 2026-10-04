const getHealth = (req, res) => {
  res.json({
    status: "ok",
    service: "api-gateway"
  });
};

module.exports = {
  getHealth
};

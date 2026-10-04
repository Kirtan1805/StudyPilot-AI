const getAuthHealth = async () => {
  const response = await fetch(
    `${process.env.AUTH_SERVICE_URL}/health`
  );

  const data = await response.json();

  return {
    status: response.status,
    data
  };
};

module.exports = {
  getAuthHealth
};

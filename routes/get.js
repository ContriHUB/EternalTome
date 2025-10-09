const handler = (req, res) => {
  const entity = req.headers['x-entity-id'] ?? null;

  res.status(200);
  res.send({ data: entity, ownerId: entity });
};

module.exports = handler;

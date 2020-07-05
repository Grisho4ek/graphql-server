const { AuthenticationError } = require('apollo-server');
const jwt = require('jsonwebtoken');
const { SECRET } = require('../config');

module.exports = context => {
  const authHeader = context.req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split('Bearer ')[1];
    if (token) {
      try {
        const user = jwt.verify(token, SECRET);
        return user;
      } catch (err) {
        throw new AuthenticationError('Invalid/Expired token');
      }
    }
    throw new Error('Token not valid');
  }
  throw new Error('Auth header must be provided');
};

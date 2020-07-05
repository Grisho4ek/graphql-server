const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const { SECRET } = require('../../config');
const { UserInputError } = require('apollo-server');
const {
  validateRegisterInput,
  validateLoginInput
} = require('../../util/validators');

const generateToken = user => {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email
    },
    SECRET,
    {
      expiresIn: '1h'
    }
  );
};

module.exports = {
  Mutation: {
    async login(_, { username, password }) {
      const { errors, valid } = validateLoginInput(username, password);
      if (!valid) {
        throw new UserInputError('Errors', { errors });
      }
      const user = await User.findOne({ username });
      if (!user) {
        errors.general = 'User not found';
        throw new UserInputError(errors.general, { errors });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        errors.general = 'User not found';
        throw new UserInputError(errors.general, { errors });
      }
      const token = generateToken(user);

      return {
        ...user._doc,
        id: user._id,
        token
      };
    },
    async register(
      _,
      { registerInput: { username, email, password, confirmPassword } }
    ) {
      const { valid, errors } = validateRegisterInput(
        username,
        password,
        confirmPassword,
        email
      );
      if (!valid) {
        throw new UserInputError('Errors', { errors });
      }
      let user;
      try {
        user = await User.findOne({
          username
        });
      } catch (error) {
        console.log(error.message);
      }
      if (user) {
        throw new UserInputError('Username is taken', {
          errros: {
            username: 'This username is taken'
          }
        });
      }
      password = await bcrypt.hash(password, 12);

      const newUser = new User({
        email,
        username,
        password,
        createdAt: new Date().toISOString()
      });

      let res;
      try {
        res = await newUser.save();
      } catch (err) {
        throw new Error(err.message);
      }

      const token = generateToken(res);

      return {
        ...res._doc,
        id: res._id,
        token
      };
    }
  }
};

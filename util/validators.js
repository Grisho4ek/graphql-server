module.exports.validateRegisterInput = (
  username,
  password,
  confirmPassword,
  email
) => {
  const errors = {};
  if (username.trim() === '') errors.username = 'Username must not be empty';

  if (email.trim() === '') {
    errors.email = 'Email must not be empty';
  } else {
    const regEx = /^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$/;
    if (!email.match(regEx)) errors.email = 'Email not valid';
  }

  if (password === '') errors.password = 'Password must not be empty';
  if (password !== confirmPassword)
    errors.confirmPassword = 'Password must match';

  return { errors, valid: Object.keys(errors).length === 0 };
};

module.exports.validateLoginInput = (username, password) => {
  const errors = {};
  if (username.trim() === '') errors.username = 'Username must not be empty';
  if (password === '') errors.password = 'Password must not be empty';
  return { errors, valid: Object.keys(errors).length === 0 };
};

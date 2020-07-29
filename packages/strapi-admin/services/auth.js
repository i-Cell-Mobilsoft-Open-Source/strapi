'use strict';

const _ = require('lodash');
const hashText = require('pbkdf2-wrapper/hashText')
const verifyHash = require('pbkdf2-wrapper/verifyHash')


const config = {
  encoding: 'hex',
  digest: 'sha512',
  hashBytes: 16,
  saltBytes: 32,
  iterations: 372791
}

const { getAbsoluteAdminUrl } = require('strapi-utils');

/**
 * hashes a password
 * @param {string} password - password to hash
 * @returns {string} hashed password
 */
const hashPassword = async (password) => await hashText(password, config);

/**
 * Validate a password
 * @param {string} password
 * @param {string} hash
 * @returns {boolean} is the password valid
 */
const validatePassword = async (password, hash) => await verifyHash(password, hash, config);

/**
 * Check login credentials
 * @param {Object} options
 * @param {string} options.email
 * @param {string} options.password
 */
const checkCredentials = async ({ email, password }) => {
  const user = await strapi.query('user', 'admin').findOne({ email });

  if (!user || !user.password) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  const isValid = await validatePassword(password, user.password);

  if (!isValid) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  if (!(user.isActive === true)) {
    return [null, false, { message: 'User not active' }];
  }

  return [null, user];
};

/**
 * Send an email to the user if it exists or do nothing
 * @param {Object} param params
 * @param {string} param.email user email for which to reset the password
 */
const forgotPassword = async ({ email } = {}) => {
  const user = await strapi.query('user', 'admin').findOne({ email, isActive: true });

  if (!user) {
    return;
  }

  const resetPasswordToken = strapi.admin.services.token.createToken();
  await strapi.admin.services.user.updateById(user.id, { resetPasswordToken });

  // Send an email to the admin.
  const url = `${getAbsoluteAdminUrl(
    strapi.config
  )}/auth/reset-password?code=${resetPasswordToken}`;
  return strapi.plugins.email.services.email
    .sendTemplatedEmail(
      {
        to: user.email,
        from: strapi.config.get('server.admin.forgotPassword.from'),
        replyTo: strapi.config.get('server.admin.forgotPassword.replyTo'),
      },
      strapi.config.get('server.admin.forgotPassword.emailTemplate'),
      {
        url,
        user: _.pick(user, ['email', 'firstname', 'lastname', 'username']),
      }
    )
    .catch(err => {
      // log error server side but do not disclose it to the user to avoid leaking informations
      strapi.log.error(err);
    });
};

/**
 * Reset a user password
 * @param {Object} param params
 * @param {string} param.resetPasswordToken token generated to request a password reset
 * @param {string} param.password new user password
 */
const resetPassword = async ({ resetPasswordToken, password } = {}) => {
  const matchingUser = await strapi
    .query('user', 'admin')
    .findOne({ resetPasswordToken, isActive: true });

  if (!matchingUser) {
    throw strapi.errors.badRequest();
  }

  return strapi.admin.services.user.updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
  });
};

module.exports = {
  checkCredentials,
  validatePassword,
  hashPassword,
  forgotPassword,
  resetPassword,
};

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


const sanitizeUser = user => {
  return _.omit(user.toJSON ? user.toJSON() : user, [
    'password',
    'resetPasswordToken',
  ]);
};

/**
 * Creates a JWT token for an administration user
 * @param {object} admon - admin user
 */
const createJwtToken = admin => {
  return strapi.plugins['users-permissions'].services.jwt.issue({
    id: admin.id,
    isAdmin: true,
  });
};

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

module.exports = {
  createJwtToken,
  sanitizeUser,
  validatePassword,
  hashPassword,
};

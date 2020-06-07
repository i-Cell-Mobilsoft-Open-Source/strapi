const moment = require('moment');

/**
 * Read the documentation (https://strapi.io/documentation/3.0.0-beta.x/concepts/services.html#core-services)
 * to customize this service
 */

module.exports = {
  addAuditData: (data, ctx, create = true) => {
    let dateField = 'insDate';
    let userField = 'insUser';
    let version = 0;
    if (!create) {
      dateField = 'modDate';
      userField = 'modUser';
      version = parseInt(data.version, 10) + 1;
    }

    return {
      ...data,
      ...{
        [dateField]: moment.utc().toDate(),
        [userField]: ctx.state && ctx.state.user ? ctx.state.user._id : ctx,
        version,
      },
    };
  },
};

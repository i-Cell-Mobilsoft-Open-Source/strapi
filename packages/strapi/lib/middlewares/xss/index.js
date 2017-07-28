'use strict';

/**
 * Module dependencies
 */

// Public node modules.
const _ = require('lodash');
const cron = require('node-schedule');

/**
 * CRON hook
 */

module.exports = strapi => {
  return {
    /**
     * Default options
     */

    defaults: {
      xss: {
        enabled: false
      }
    },

    /**
     * Initialize the hook
     */

    initialize: function(cb) {
      strapi.app.use(
        strapi.koaMiddlewares.convert(
          strapi.koaMiddlewares.lusca.xssProtection({
            enabled: strapi.config.middleware.settings.xss.enabled,
            mode: strapi.config.middleware.settings.xss.mode
          })
        )
      );

      cb();
    }
  };
};

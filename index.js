/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate-authcode-simple-secrets')
  , ss = require("simple-secrets")
  , bitfield = require('bitfield');

/**
 * Simple Secrets issue token for consulate
 *
 * @param {Object} options
 * @return {Function}
 */

module.exports = function(options, db) {
  // Check that they gave us a key to sign
  if (!options || !options.key) throw new Error("Missing a `key` for authcode simple-secrets signer");

  // Create a sender
  var key = new Buffer(options.key, 'hex')
    , sender = ss(key);

  function register(app, save) {

    // Save the `scopes` callback for compression
    var getScopes = app.callback('scopes');

    // Allow the consumer to map scopes to a compressed enum value
    var pack = options.packScope || bitfield.pack
      , unpack = options.unpackScope || bitfield.unpack;

    // Register creating an auth code
    app.createAuthorizationCode(function(client, redirectURI, user, ares, done) {
      // Get the available scopes to pack our list of scopes
      debug('getting available scopes');
      getScopes(function(err, scopes) {
        debug('got available scopes', scopes);
        if (err) return done(err);

        // Pack info about the auth code in the auth code itself
        // NOTE: we use short variable names so the code doesn't get too big
        debug('packing code', client, redirectURI, user, ares);
        var code = sender.pack({
          c: client.id,
          u: user.id,
          s: pack(ares.scope || client.scope, scopes),
          r: redirectURI
        });
        debug('packed code', client, redirectURI, user, ares, code);

        // Save a flag that this code has not been used yet
        // NOTE: it's recommended that an expiration also be set for about 10 minutes
        debug('saving code', code);
        db.save(code, function(err) {
          debug('saved code', code, err);
          done(err, code);
        });
      });
    });

    // Register getting an auth code
    app.authorizationCode(function(code, done) {
      // Check that this code has not been used
      debug('validating code', code)
      db.validate(code, function(err, isValid) {
        debug('validated code', code, isValid);
        if (err) return done(err);
        if (!isValid) return done(null, null);
        
        // Get the available scopes to unpack our compressed list
        debug('getting available scopes');
        getScopes(function(err, scopes) {
          debug('got available scopes', scopes);
          if (err) return done(err);

          // Unpack the info about the auth code
          debug('unpacking code', code);
          var authInfo = sender.unpack(code);
          debug('unpacked code', code, authInfo);

          // It wasn't valid
          if (!authInfo) return done(null, null);

          // Translate what we stored into something consulate understands
          var consulateInfo = {
            client_id: authInfo.c,
            user_id: authInfo.u,
            scope: unpack(new Buffer(authInfo.s), scopes),
            redirect_uri: authInfo.r
          };

          debug('translated code', code, consulateInfo);
          done(null, consulateInfo);
        });
      });
    });

    // Register invalidating an auth code
    app.invalidateAuthorizationCode(function(code, done) {
      // Mark the code as invalid so it can't be used anymore
      debug('invalidating code', code);
      db.invalidate(code, function(err) {
        debug('invalidated code', code);
        done(err);
      });
    });
  };

  // Expose the sender
  register.sender = sender;

  return register;
};

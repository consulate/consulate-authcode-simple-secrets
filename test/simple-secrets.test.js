/**
 * Module dependencies
 */
var should = require('should')
  , authcode = require('..')
  , ss = require('simple-secrets')
  , bitfield = require('bitfield');

/**
 * Defines
 */

var SECRET = '3b6006d164bae955136a5befea9d0e4a50c22a2f7be5d65c2fd67752625deee3';

describe('consulate-authcode-simple-secrets', function() {

  var app, db;

  var signer = ss(new Buffer(SECRET, 'hex'))
    , availableScopes = ['user:email', 'user:name', 'user:address'];

  beforeEach(function() {
    app = {
      'createAuthorizationCode': function(fn) {
        app.callbacks.createAuthorizationCode = fn;
      },
      'authorizationCode': function(fn) {
        app.callbacks.authorizationCode = fn;
      },
      'invalidateAuthorizationCode': function(fn) {
        app.callbacks.invalidateAuthorizationCode = fn;
      },
      'callback': function() {
        return function(done) {
          done(null, availableScopes);
        }
      },
      callbacks: {}
    };

    var validCodes = {};

    db = {
      save: function (code, done) {
        validCodes[code] = true;
        done()
      },
      validate: function (code, done) {
        done(null, !!validCodes[code]);
      },
      invalidate: function (code, done) {
        delete validCodes[code];
        done();
      }
    }
  });

  it('should register a `issueToken` callback', function() {
    var options = {key: SECRET}
      , instance = authcode(options, db);

    instance(app);

    should.exist(app.callbacks.createAuthorizationCode);
    should.exist(app.callbacks.authorizationCode);
    should.exist(app.callbacks.invalidateAuthorizationCode);
    Object.keys(app.callbacks).should.have.length(3);
  });

  it('should issue a valid authcode', function(done) {
    var instance = authcode({key: SECRET}, db)(app)

    var client = {id: 'clientId'}
      , redirectURI = 'https:/example.com'
      , user = {id: 'userId'}
      , ares = {scope: ['user:email', 'user:name']};

    app.callbacks.createAuthorizationCode(client, redirectURI, user, ares, function(err, code) {
      app.callbacks.authorizationCode(code, function(err, authInfo) {
        if (err) return done(err);
        authInfo.client_id.should.eql(client.id);
        authInfo.redirect_uri.should.eql(redirectURI);
        authInfo.user_id.should.eql(user.id);
        authInfo.scope.should.eql(ares.scope);
        app.callbacks.invalidateAuthorizationCode(code, function(err) {
          if (err) return done(err);
          app.callbacks.authorizationCode(code, function(err, invalidatedInfo) {
            if (err) return done(err);
            should.not.exist(invalidatedInfo);
            done();
          });
        });
      });
    });
  });

});

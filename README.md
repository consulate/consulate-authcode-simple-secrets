consulate-authcode-simple-secrets [![Build Status](https://travis-ci.org/consulate/consulate-authcode-simple-secrets.png?branch=master)](https://travis-ci.org/consulate/consulate-authcode-simple-secrets)
========================

[simple-secrets](https://github.com/timshadel/simple-secrets) authcode plugin for [consulate](https://github.com/consulate/consulate)

Usage
-----

Just register `consulate-authcode-simple-secrets` as a plugin with your [consulate](https://github.com/consulate/consulate) server:

```js
var consulate = require('consulate')
  , authcode = require('consulate-authcode-simple-secrets');

var app = consulate();

// Give a few db methods
var db = {
  // Save a simple flag to the db that the code hasn't been used
  save: function (code, done) {
    // do db work here
    done(err);
  },
  // Validate the code exists and has not been used
  validate: function (code, done) {
    // do db work here
    done(err, isValid);
  },
  // Invalidate a code so it cannot be used again
  invalidate: function (code, done) {
    // do db work here
    done(err);
  }
};

app.plugin(authcode({
  key: '3b6006d164bae955136a5befea9d0e4a50c22a2f7be5d65c2fd67752625deee3'
}, db));
```

`NOTE` It is also recommended that an expiration of about 10 minutes be set on valid authorization codes

Tests
-----

```sh
$ npm test
```

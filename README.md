# express-tokenware

Flexible and minimalist token-based authentication middleware for [express](http://expressjs.com/).

```javascript
var tokenware = require('express-tokenware')('mySecretKey');
app.use(tokenware.setHeaders);

app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware.sign,
  tokenware.send
);

app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    if (req.decodedBearerToken) {
      // success. Do something with req.decodedBearerToken here
    } else {
      // handle anonymous (invalid token) request
    }
  }
);

app.listen(3000);
```

## Installation

```bash
$ npm install express-tokenware
```

## Features

* Uses [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT)
* Flexible data structure - store whatever you like in the token
* Provides tokens on sign-in/authentication
* Extracts bearer tokens from request header
* Checks tokens on incoming requests
* Handles anonymous requests
* Rejects expired tokens
* Allows custom error handling
* (future) Checks revoked tokens

## Philosophy

Be unopinionated: don't limit database or architecture options, simply provide basic token functionality that's easy to integrate with the stack.

## Dependencies

`express-tokenware` depends on and adopts variable naming from [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Documentation

Where not specified, variables are defined as per [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) documentation.

### Configuration
Define `express-tokenware` in your project by calling:

```javascript
var tokenware = require('express-tokenware')(secretOrPrivateKey, [options]);
```

`options` refers to configuration parameters that will govern both signing and verification of bearer tokens. It must be an object literal that may include any or all of the following 5 parameters:

* `algorithm`
* `expiresIn`
* `audience`
* `issuer`
* `allowAnonymous` (default: false)

Attach the `tokenware.setHeaders` middleware to allow bearer tokens within a request header:

```javascript
app.use(tokenware.setHeaders);
```

### Sign-in/authentication
Once your application has authenticated a user and created a payload for the bearer token, use the `tokenware.sign` middleware to sign the token. This will:

1. look for the payload at `req.bearerTokenPayload`,
2. store a signed bearer token at `req.signedBearerToken`, and
3. call the next middleware function.

Subsequent middleware functions may perform any number of actions on the signed bearer token, such as storing it in a database or sending it to the user, depending on your application design. `express-tokenware` does not assume any particular database technology  and leaves database interaction up to your application middleware. It provides a convenience middleware function called `tokenware.send` for sending the signed bearer token to the user at `res.signedBearerToken`, along with a HTTP header status of `200`.

This example is a simple implementation of `tokenware.sign` and `tokenware.send`:

```javascript
app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware.sign,
  tokenware.send
);
```

This example adds some complexity by performing an action on the signed bearer token before sending it as a response:

```javascript
app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware.sign,
  someTokenStorageMiddleware,
  tokenware.send
);
```

### Extracting signed bearer tokens from incoming requests

`express-tokenware` looks for tokens in the `authorization` header in the form of `'Bearer token'` (case-sensitive).

### Verifying signed bearer tokens

The recommended way to verify signed bearer tokens is the use the `tokenware.verify` middleware. Although you may wish to verify against tokens stored in a database, this is not a safe approach as the stored tokens may be tampered by an attacker. Using the middleware provided ensures that the token has a valid signature.

If `tokenware.verify` successfully verifies the signed bearer token, it will attach the decoded bearer token to `req.decodedBearerToken` and call the next middleware function. If it fails to verify the token, it will invoke an error which will be passed to the error-handling middleware in the stack. In the examples within this section, the error is passed to the `token.verificationErrorHandler` middleware for error-handling.

This example is a simple implementation of `tokenware.verify` with default configuration:

```javascript
app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    // success. Do something with req.decodedBearerToken here
  },
  tokenware.verificationErrorHandler
);
```

Invalid tokens are treated as errors and are passed to `token.verificationErrorHandler`.

This example handles anonymous requests (allowed through setting `options.allowAnonymous` to `true` in the configuration parameters).

```javascript
app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    if (req.decodedBearerToken) {
      // success. Do something with req.decodedBearerToken here
    } else {
       // handle anonymous (invalid token) request
    }
  }
);
```

In the above example, there is no need to call `token.verificationErrorHandler` because invalid tokens are not treated as errors.

### Verification error handling

Invalid signed bearer tokens are treated as errors and are passed to the error-handling middleware in the stack. `express-tokenware` provides `tokenware.verificationErrorHandler` as a convenient error-handling middleware, however, it may be replaced with a custom middleware.

`tokenware.verify` passes two types of errors:

* expired token error, and
* invalid token error.

Refer to [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) documentation for detailed descriptions of the values passed to the `err` argument.

If anonymous requests are allowed (through the configuration parameter `options.allowAnonymous`) then invalid tokens are not treated as an error. In this case, an error-handling middleware may not be necessary.
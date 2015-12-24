# express-tokenware

Flexible and minimalist token-based authentication middleware for [express](http://expressjs.com/).

```javascript
var tokenware = require('express-tokenware')('mySecretKey');
app.use(tokenware);

app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware
);

app.get('/myProtectedPath',
  function (req, res, next) {
    // success, do something with req.decodedBearerToken here
  });

app.listen(3000);
```

## Installation

```bash
$ npm install express-tokenware
```

## Testing

All `express-tokenware` behaviours have been tested using [jasmine](https://www.npmjs.com/package/jasmine).

```bash
$ npm test
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
* Checks revoked tokens

## Philosophy

Be unopinionated: don't limit database or architecture options, simply provide basic token functionality that's easy to integrate with the stack.

## Documentation

Where not specified, variables are defined as per [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) documentation.

### Configuration
Include `express-tokenware` in your project by calling:

```javascript
var tokenware = require('express-tokenware')(secretOrPrivateKey, [options, isRevokedToken]);
```

`options` refers to configuration parameters that govern both signing and verification of bearer tokens. It must be an object literal that may include any or all of the following 7 parameters:

* `algorithm`
* `expiresIn`
* `audience`
* `issuer`
* `allowAnonymous` set this to `true` to allow anonymous requests (default: `false`)
* `autoSendToken` set this to `false` to prevent sending a token as soon as it is signed (default: `true`)
* `handleErrors` set this to `false` to use a custom error-handling middleware (default: `true`)

`isRevokedToken` is a callback which can accept a token string and return `true` if the token has been revoked or `false` if the token has not been revoked.

### Initialization

Attach `tokenware` to your application. This will allow bearer tokens to be received and it will verify any bearer tokens found on incoming requests:

```javascript
var app = express();
app.use(tokenware);
```

### Sign-in/authentication
Once your application has authenticated a user and created a payload for the bearer token, use `tokenware` again to sign and send the token. This will:

1. look for the payload at `req.bearerTokenPayload`,
2. store a signed bearer token at `req.signedBearerToken`,
3. send the signed token to the user at `res.signedBearerToken`, along with an `OK` HTTP header status of `200`, and
3. call the next middleware function.

This example is a simple implementation of sign-in/authentication:

```javascript
app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware
);
```

If you would not like to send the token immediately upon signing, set the configuration option `autoSendToken` to `false` and provide your own middleware for responding to the request.

### Extracting signed bearer tokens from incoming requests

`express-tokenware` looks for tokens in the `authorization` header in the form of `'Bearer <token>'` (case-sensitive).

### Verifying signed bearer tokens

`express-tokenware` automatically verifies any bearer token found in an incoming request. This guarantees that the token has a valid signature. An alternate approach of verifying against tokens stored in a database is not supported by this module, as the stored tokens may be tampered with by an attacker.

If `tokenware` successfully verifies the signed bearer token, it will attach the decoded bearer token to `req.decodedBearerToken` and call the next middleware function. If it fails to verify the token, it will invoke an error which will be passed to the error-handling middleware in the stack.

This example verifies tokens with the default configuration:

```javascript
app.get('/myProtectedPath',
  function (req, res, next) {
    // success, do something with req.decodedBearerToken here
  }
);
```
If you would like to allow anonymous requests to your server, set the configuration option `allowAnonymous` to `true`. Subsequent middleware can detect anonymous requests by checking `req.isAnonymous`. This example demonstrates how to differentiate between authorized and anonymous requests:

```javascript
app.get('/myProtectedPath',
  function (req, res, next) {
    if (req.isAnonymous) {
      // anonymous request
    } else {
      // not anonymous, do something with req.decodedBearerToken here
    }
  }
);
```

## Error handling

`express-tokenware` comes with a built-in error-handling, however, it may be replaced with a custom middleware. This section provides information on building a custom error-handling middleware.

The error object passed to the middleware will have at least two properties:

* `name`
* `message`

This table lists the errors sent by `express-tokenware`:

Name|Message
---|---
JsonWebTokenError|(variable, generated by [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken))
malformedAuthorizationHeader|Authorization header is malformed, should be in the form of: Bearer <token>
revokedToken|Request authorization was previously revoked
TokenExpiredError|jwt expired (generated by [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken))

If anonymous requests are allowed (through the configuration parameter `allowAnonymous`) then unauthorized requests are not treated as an error. In this case, an error-handling middleware may not be necessary.
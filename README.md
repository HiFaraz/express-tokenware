# express-tokenware

Flexible and minimalist token-based authentication middleware for [express](http://expressjs.com/).

```javascript
var tokenware = require('express-tokenware')('mySecretKey');
app.use(tokenware.setHeaders);

app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware.sign,
  tokenware.send,
  tokenware.errorHandler
);

app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    // success, do something with req.decodedBearerToken here
  },
  tokenware.errorHandler
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
* Checks revoked tokens

## Philosophy

Be unopinionated: don't limit database or architecture options, simply provide basic token functionality that's easy to integrate with the stack.

## Documentation

Where not specified, variables are defined as per [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) documentation.

### Configuration
Define `express-tokenware` in your project by calling:

```javascript
var tokenware = require('express-tokenware')(secretOrPrivateKey, [options, isRevokedToken]);
```

`options` refers to configuration parameters that will govern both signing and verification of bearer tokens. It must be an object literal that may include any or all of the following 5 parameters:

* `algorithm`
* `expiresIn`
* `audience`
* `issuer`
* `allowAnonymous` set this to `true` to allow anonymous requests (default: false)

`isRevokedToken` is a callback which can accept a token string and return `true` if the token has been revoked or `false` if the token has not been revoked.

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
  tokenware.send,
  tokenware.errorHandler
);
```

This example adds some complexity by performing an action on the signed bearer token before sending it as a response:

```javascript
app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware,
  tokenware.sign,
  someTokenStorageMiddleware,
  tokenware.send,
  tokenware.errorHandler
);
```

### Extracting signed bearer tokens from incoming requests

`express-tokenware` looks for tokens in the `authorization` header in the form of `'Bearer <token>'` (case-sensitive).

### Verifying signed bearer tokens

The recommended way to verify signed bearer tokens is the use the `tokenware.verify` middleware. Although you may wish to verify against tokens stored in a database, this is not a safe approach as the stored tokens may be tampered by an attacker. Using the middleware provided ensures that the token has a valid signature.

If `tokenware.verify` successfully verifies the signed bearer token, it will attach the decoded bearer token to `req.decodedBearerToken` and call the next middleware function. If it fails to verify the token, it will invoke an error which will be passed to the error-handling middleware in the stack.

This example verifies tokens with the default configuration:

```javascript
app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    // success, do something with req.decodedBearerToken here
  },
  tokenware.errorHandler
);
```
Invalid tokens are treated as errors and are passed to `token.errorHandler`.

In the case of anonymous requests, `tokenware.verify` sets `req.isAnonymous` to `true`. This example verifies tokens and also detects anonymous requests (allowed through configuration parameters):

```javascript
app.get('/myProtectedPath',
  tokenware.verify,
  function (req, res, next) {
    if (req.isAnonymous) {
      // anonymous request
    } else {
      // not anonymous, do something with req.decodedBearerToken here
    }
  }
);
```

In the above example, there is no need to call `token.errorHandler` because invalid tokens are not treated as errors.

## Error handling

`express-tokenware` provides `tokenware.errorHandler` as a convenient error-handling middleware, however, it may be replaced with a custom middleware. This section provides information on building a custom error-handling middleware.

The error object passed to the middleware will have at least two properties:

* `name`
* `message`

This table lists the errors sent by `express-tokenware`:

Name|Message|Invoked by
---|---|---
payloadMissing|Missing bearer token payload|`tokenware.send`
signedBearerTokenMissing|Missing signed bearer token|`tokenware.send`
JsonWebTokenError|(variable, generated by [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken))|`tokenware.verify`
malformedAuthorizationHeader|Authorization header is malformed, should be in the form of: Bearer <token>|`tokenware.verify`
noAuthorizationHeader|Request is missing authorization header|`tokenware.verify`
revokedToken|Request authorization was previously revoked|`tokenware.verify`
TokenExpiredError|jwt expired (generated by auth0/node-jsonwebtoken)|`tokenware.verify`
unknown|Could not verify token, likely that "iat" claim is missing from the token|`tokenware.verify`

If anonymous requests are allowed (through the configuration parameter `options.allowAnonymous`) then invalid tokens are not treated as an error. In this case, an error-handling middleware may not be necessary.
# express-tokenware

Sign and verify tokens for your [express](http://expressjs.com/) app with one middleware.

[![Greenkeeper badge](https://badges.greenkeeper.io/HiFaraz/express-tokenware.svg)](https://greenkeeper.io/) [![Linux Build][travis-image]][travis-url]

**NOTE: this is a pre-production version, and the module interfaces and functionality are not stable yet.**

```javascript
var tokenware = require('express-tokenware')('mySecretKey');
var app = tokenware(express);

app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware
);

app.get('/myProtectedPath',
  function (req, res, next) {
    // success, do something with req.decodedBearerToken here
  });

app.listen(3000);
```

## 1. Installation

```bash
$ npm install express-tokenware
```

## 2. Testing

All `express-tokenware` behaviours have been tested using [jasmine](https://www.npmjs.com/package/jasmine).

```bash
$ npm test
```

## 3. Features / high-level behaviours

* Uses [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT)
* Flexible data structure - store whatever you like in the token
* Provides tokens on sign-in/authentication
* Extracts bearer tokens from request header
* Checks tokens on incoming requests
* Handles anonymous requests
* Rejects expired tokens
* Allows custom error handling
* Checks revoked tokens

## 4. Philosophy

* behaviour driven-development
* do the work for the user, such as sandwiching the stack with one function
* unopinionated, provide an interface that can be used with any architecture or database


## 5. Documentation

Where not specified, variables are defined as per [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) documentation.

### 5.1 Configuration
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
* `handleErrors` set this to `false` to use a custom error-handling middleware (default: `true`)

`isRevokedToken` is a callback which can accept a token string and return `true` if the token has been revoked or `false` if the token has not been revoked.

### 5.2 Initialization

Attach `tokenware` to your application. This will allow bearer tokens to be received, verify any bearer tokens found on incoming requests, and send signed tokens on responses with token payloads.

```javascript
var app = tokenware(express);
```

`express` is injected as a dependency into `tokenware`. This ensures that `tokenware` is both the first and last middleware to execute, which allows it to be used for both authenticating users and authorizing requests.

### 5.3 Sign-in/authentication
Once your application has authenticated a user and created a payload for the bearer token, create a payload **object** at `res.locals.bearerTokenPayload` and call `next()` in your last route middleware. `tokenware` will send the signed token to the user as a JSON object `{"signedBearerToken": <token>}`, along with an `OK` HTTP header status of `200`.

This example is a simple implementation of sign-in/authentication:

```javascript
app.get('/authenticate',
  someAuthenticationMiddleware,
  somePayloadCreationMiddleware // this **must** call `next()` to send a signed token
);
```

### 5.4 Extracting signed bearer tokens from incoming requests

`express-tokenware` looks for tokens in the `authorization` header in the form of `'Bearer <token>'` (case-sensitive). Set the response headers appropriately to allow cross-origin resource sharing (CORS).

### 5.5 Verifying signed bearer tokens

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

## 6. Error handling

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

## 7. Issues and pull requests

Feedback and contribution are highly encouraged! Please report feedback through the [Github issue tracker](https://github.com/HiFaraz/express-tokenware/issues). To submit code, please fork the [Github repository](https://github.com/HiFaraz/express-tokenware) and send a pull request.

## 8. Licence

[MIT](LICENSE)

[travis-image]: https://travis-ci.org/HiFaraz/express-tokenware.svg?branch=master
[travis-url]: https://travis-ci.org/HiFaraz/express-tokenware
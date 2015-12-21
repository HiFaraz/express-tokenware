# express-tokenware
Express middleware that signs and verifies JSON Web Tokens (JWT) and sets `req.authorizationToken`.

This module enables your Express application to apply token-based authentication using [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT).

## Dependencies

* [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

## Install

    $ npm install express-tokenware

## Usage

    var tokenware = require('tokenware')(secretOrPrivateKey, options);

`secretOrPrivateKey` is a string or buffer containing either the secret or a private key

`options`: (optional)

* `algorithm` (default: same as auth0/node-jsonwebtoken)
* `expiresIn`
* `audience`
* `issuer`
* `allowAnonymous` (default: false)

For explanation on `algorithm`, `expiresIn`, `audience`, and `issuer` defaults consult [auth0/node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken).

```javascript
app.use(token.install);

app.get('/authenticate', checkCredentials, token.sign, token.send);

app.get('/api/*', token.verify, function (req, res, next) {
	if (req.authorizationToken) {
		// verified token, can proceed as is, or check if revoked
		res.send(req.authorizationToken);
	} else res.end(); // anonymous request
}, function (err, req, res, next) { // or use token.verificationErrorHandler
	if (err.name == 'TokenExpiredError') res.status(401).json({
		error: 'Expired authorization JSON web token.'
	});
	else res.status(401).json({
		error: 'Unauthorized request.'
	});
});
```
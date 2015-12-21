var jsonwebtoken = require('jsonwebtoken');

module.exports = function (secretOrPrivateKey, options) {
	options = options || {};
	options.sign = {};
	options.verify = {};
	options.allowAnonymous = options.allowAnonymous || false;
	if (options.algorithm) {
		options.sign.algorithm = options.algorithm;
		options.verify.algorithms = options.algorithm;
	}
	if (options.audience) {
		options.sign.audience = options.audience;
		options.verify.audience = options.audience;
	}
	if (options.issuer) {
		options.sign.issuer = options.issuer;
		options.verify.issuer = options.issuer;
	}
	if (options.expiresIn) {
		options.sign.expiresIn = options.expiresIn;
		options.verify.maxAge = options.expiresIn;
		options.verify.ignoreExpiration = false;
	} else options.verify.ignoreExpiration = true;
	if (options.ignoreExpiration) options.verify.ignoreExpiration = options.ignoreExpiration;

	return {
		install: function (req, res, next) {
			res.setHeader('Access-Control-Allow-Origin', '*');
			res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
			res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
			next();
		},
		sign: function (req, res, next) {
			if (!req.payload) req.err = 'No payload provided to create autorization JSON web token.';
			else req.token = jsonwebtoken.sign(req.payload, secretOrPrivateKey, options.sign);
			next();
		},
		send: function (req, res, next) {
			if (req.err || !req.token) res.status(500).json({
				error: req.err || 'Missing an autorization JSON web token to send.'
			});
			else res.status(200).json({
				token: req.token
			});
		},
		verify: function (req, res, next) {
			if (typeof req.headers['authorization'] == 'undefined') res.status(500).json({
				error: 'No authorization header provided in request.'
			});
			else {
				try {
					jsonwebtoken.verify(req.headers["authorization"].split(" ")[1], secretOrPrivateKey, options.verify, function (err, decoded) {
						if (err) {
							if (options.allowAnonymous) next();
							else next(err);
						} else {
							req.authorizationToken = decoded;
							next();
						}
					});
				} catch (err) {
					res.status(400).json({
						error: 'Could not verify token, likely that "iat" claim is missing from the token.'
					});
				}
			}
		},
		verificationErrorHandler: function (err, req, res, next) {
			if (err.name == 'TokenExpiredError') res.status(401).json({
				error: 'Expired authorization JSON web token.'
			});
			else res.status(401).json({
				error: 'Unauthorized request.'
			});
		}
	};
}
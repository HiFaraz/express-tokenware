var jsonwebtoken = require('jsonwebtoken'),
	httpCodes = require('http-codes');
var _name = 'express-tokenware';

module.exports = function (secretOrPrivateKey, options, isRevokedToken) {
	isRevokedToken = isRevokedToken || (function () {
		return false;
	});
	if (typeof options == 'function') {
		isRevokedToken = options;
		options = {};
	}
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

	var _rejectVerification = function (error, req, next) {
		if (options.allowAnonymous) {
			req.isAnonymous = true;
			next();
		} else {
			next(error);
		}
	};

	var _error = function (name, message, data) {
		data = data || {};
		if (!name) {
			console.warn(_name + ' input argument *name* is missing');
			return;
		}
		if (data.name) console.warn(_name + ' input agrument *data.name* was overwritten');
		if (data.message) console.warn(_name + ' input agrument *data.messaage* was overwritten');
		data.name = name;
		data.message = message || {};
		return data;
	};

	var _exports = {};
	_exports.setHeaders = function (req, res, next) {
		res.setHeader('Access-Control-Allow-Origin', '*');
		res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
		res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
		next();
	};
	_exports.sign = function (req, res, next) {
		if (!req.bearerTokenPayload) next(_error('payloadMissing', 'Missing bearer token payload'));
		else req.signedBearerToken = jsonwebtoken.sign(req.bearerTokenPayload, secretOrPrivateKey, options.sign);
		next();
	};
	_exports.send = function (req, res, next) {
		if (!req.signedBearerToken) next(_error('signedBearerTokenMissing', 'Missing signed bearer token'));
		else res.status(httpCodes.OK).json({
			signedBearerToken: req.signedBearerToken
		});
	};
	_exports.verify = function (req, res, next) {
		var authorizationHeader = req.headers['authorization'],
			bearerTokenPrefix = authorizationHeader.split(" ")[0],
			bearerToken = authorizationHeader.split(" ")[1];

		if (typeof authorizationHeader == 'undefined') {
			_rejectVerification(_error('noAuthorizationHeader', 'Request is missing authorization header'), req, next);
		} else if (bearerTokenPrefix !== 'Bearer' || typeof bearerToken == 'undefined') {
			_rejectVerification(_error('malformedAuthorizationHeader', 'Authorization header is malformed, should be in the form of: Bearer <token>'), req, next);
		} else {
			try {
				jsonwebtoken.verify(bearerToken, secretOrPrivateKey, options.verify, function (err, decodedBearerToken) {
					if (err) {
						_rejectVerification(err, req, next);
					} else {
						if (isRevokedToken(bearerToken)) {
							_rejectVerification(_error('revokedToken', 'Request authorization was previously revoked'), req, next);
						} else {
							req.decodedBearerToken = decodedBearerToken;
							next();
						}
					}
				});
			} catch (err) {
				_rejectVerification(_error('unknown', 'Could not verify token, likely that "iat" claim is missing from the token'), req, next);
			}
		}
	};
	_exports.errorHandler = function (err, req, res, next) {
		var _sendError = function (code, error, warn) {
			if (code instanceOf Array) {
				error = code[1] || '';
				warn = code[2] || false;
				code = code[0];
			}

			if (warn && err.hasOwnProperty('message')) console.warn(err.message);

			res.status(code).send({
				error: (typeof error == 'string') ? error : error.message
			});
		};

		var errorResponses = {
			JsonWebTokenError: [httpCodes.UNAUTHORIZED, 'Unauthorized request'],
			malformedAuthorizationHeader: httpCodes.BAD_REQUEST,
			noAuthorizationHeader: httpCodes.BAD_REQUEST,
			payloadMissing: [httpCodes.INTERNAL_SERVER_ERROR, err, true],
			revokedToken: httpCodes.UNAUTHORIZED,
			signedBearerTokenMissing: [httpCodes.INTERNAL_SERVER_ERROR, err, true],
			TokenExpiredError: [httpCodes.UNAUTHORIZED, 'Expired request authorization'],
			unknown: httpCodes.BAD_REQUEST
		};

		if (errorResponses.hasOwnProperty(err.name)) {
			var response = errorResponses[err.name];
			if (typeof response == 'number') _sendError(response, err);
			else if (typeof response == 'object') _sendError(response);
			else if (typeof response == 'function') response(err);
		} else {
			console.warn(_name + ' unknown error passed to built-in error handler: (' + err.name + ', ' + err.message + ')');
			_sendError(httpCodes.INTERNAL_SERVER_ERROR, 'Unknown internal server error');
		}

		next();
	};

	return _exports;
}
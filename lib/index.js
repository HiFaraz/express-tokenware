var _name = 'express-tokenware';

var jsonwebtoken = require('jsonwebtoken');
var http = require('http');
var httpCodes = require('http-codes');
var colors = require('colors');
var debugStack = require('debug-stack');
var _error = require('./error');
var defaults = require('defaults');

console.warn('WARNING!'.white.bgRed.bold + ' ' + _name + ' is a pre-production version!');

var applyDefaultOptions = function (options) {
	var debug = debugStack(_name + ' configuration');
	options = defaults(options, {
		allowAnonymous: false,
		autoSendToken: true,
		debug: false,
		handleErrors: true
	});

	options.sign = {};
	options.verify = {};

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
	//	if (options.debug) {
	//		console.log((_name + ' initialized, options:').white.bgBlue);
	//		console.log(options);
	//		console.log('\n');
	//	}

	debug(options);
	if (options.debug) debug.print();

	return options;
};

module.exports = function (secretOrPrivateKey, options, isRevokedToken) {
	isRevokedToken = isRevokedToken || (function () {
		return false;
	});
	if (typeof options == 'function') {
		isRevokedToken = options;
		options = {};
	}

	options = applyDefaultOptions(options);

	var _middleware = function (role) {
		return function tokenware(req, res, next) {
			var debug = debugStack(_name);

			debug('tokenware called with ' + role);

			var _errorHandler = function (errorToHandle) {
				var _sendError = function (statusCode, errorToSend, warnInConsole) {
					if (statusCode && statusCode instanceof Array) {
						errorToSend = statusCode[1] || '';
						warnInConsole = statusCode[2] || false;
						statusCode = statusCode[0];
					}

					if (warnInConsole && errorToSend.hasOwnProperty('message')) console.warn(errorToSend.message);

					res.status(statusCode).send({
						error: (typeof errorToSend == 'string') ? errorToSend : errorToSend.message
					});
				};

				var _responseTable = {
					JsonWebTokenError: [httpCodes.UNAUTHORIZED, 'Unauthorized request'],
					malformedAuthorizationHeader: httpCodes.BAD_REQUEST,
					revokedToken: httpCodes.UNAUTHORIZED,
					TokenExpiredError: [httpCodes.UNAUTHORIZED, 'Expired request authorization'],
					unknown: httpCodes.BAD_REQUEST
				};

				if (_responseTable.hasOwnProperty(errorToHandle.name)) {
					var _response = _responseTable[errorToHandle.name];
					if (typeof _response == 'number') _sendError(_response, errorToHandle);
					else if (typeof _response == 'object') _sendError(_response);
					else if (typeof _response == 'function') _response(errorToHandle);
				} else {
					console.warn(_name + ' unknown error passed to built-in error handler: (' + errorToHandle.name + ', ' + errorToHandle.message + ')');
					_sendError(httpCodes.INTERNAL_SERVER_ERROR, 'Unknown internal server error');
				}
			};

			var _throw = function (error) {
				if (options.handleErrors) {
					debug('error handled internally');
					_errorHandler(error);
				} else {
					debug('error passed to next');
					req.tokenwareError = error;
				}
			};

			var _rejectToken = function (error) {
				debug('token rejected: ' + error.name + ', ' + error.message);
				if (options.allowAnonymous) req.isAnonymous = true;
				else _throw(error);
			};

			if (!res.headersSent) {
				res.setHeader('Access-Control-Allow-Origin', '*');
				res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
				res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
				debug('set headers');
			}

			var authorizationHeader = req.headers['authorization'],
				bearerTokenPrefix = (authorizationHeader) ? authorizationHeader.split(" ")[0] : '',
				bearerToken = (authorizationHeader) ? authorizationHeader.split(" ")[1] : undefined;

			var _hasBearerTokenPayload = res.bearerTokenPayload;
			var _hasAuthorizationHeader = typeof authorizationHeader !== 'undefined';
			var _authorizationHeaderIsValid = bearerTokenPrefix == 'Bearer' && typeof bearerToken !== 'undefined';

			if (_hasBearerTokenPayload && role == 'authentication') {
				debug('payload found');
				res.signedBearerToken = jsonwebtoken.sign(res.bearerTokenPayload, secretOrPrivateKey, options.sign);
				debug('token signed');
				if (options.autoSendToken) {
					res.status(httpCodes.OK).json({
						signedBearerToken: res.signedBearerToken
					});
					debug('token sent');
				}
			}

			if (_hasAuthorizationHeader && role == 'authorization') {
				debug('authorization header found');
				if (_authorizationHeaderIsValid) {
					debug('token found in authorization header');
					try {
						var _decodedBearerToken = jsonwebtoken.verify(bearerToken, secretOrPrivateKey, options.verify);
						if (isRevokedToken(bearerToken)) {
							_rejectToken(_error('revokedToken', 'Request authorization was previously revoked'));
						} else {
							req.decodedBearerToken = _decodedBearerToken;
							debug('token decoded');
						}
					} catch (error) {
						_rejectToken(error);
					}
				} else _rejectToken(_error('malformedAuthorizationHeader', 'Authorization header is malformed, should be in the form of: Bearer <token>'));
			} else req.isAnonymous = true;

			if (options.debug) debug.print();

			if (req.tokenwareError) next(req.tokenwareError);
			else next();
		};
	};

	return function (express) {
		var expressApp = express();
		expressApp.use(_middleware('authorization'));
		expressApp.listen = function listen() {
			expressApp.use(_middleware('authentication'));
			var server = http.createServer(this);
			return server.listen.apply(server, arguments);
		};
		return expressApp;
	};
}
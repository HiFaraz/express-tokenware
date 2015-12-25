var jsonwebtoken = require('jsonwebtoken'),
	http = require('http'),
	httpCodes = require('http-codes');
var _name = 'express-tokenware';
var colors = require('colors');

console.warn('WARNING!'.white.bgRed.bold + ' ' + _name + ' is a pre-production version!')

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
	(!options.hasOwnProperty('autoSendToken')) ? options.autoSendToken = true: true;
	(!options.hasOwnProperty('handleErrors')) ? options.handleErrors = true: true;
	options.allowAnonymous = options.allowAnonymous || false;
	options.debug = options.debug || false;
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
	if (options.debug) {
		console.log(_name + ' initialized, options:');
		console.log(options);
		console.log('\n');
	}

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

	var _middleware = function (role) {
		return function tokenware(req, res, next) {
			var _report = function (action) {
				if (!req.tokenwareReport) req.tokenwareReport = {};
				req.tokenwareReport[action] = true;
			};

			_report('tokenware called');

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
					_report('error handled internally');
					_errorHandler(error);
				} else {
					_report('error passed to next');
					req.tokenwareError = error;
				}
			};

			var _rejectToken = function (error) {
				_report('token rejected: ' + error.name + ', ' + error.message);
				if (options.allowAnonymous) req.isAnonymous = true;
				else _throw(error);
			};

			if (!res.headersSent) {
				res.setHeader('Access-Control-Allow-Origin', '*');
				res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
				res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
				_report('set headers');
			}

			var authorizationHeader = req.headers['authorization'],
				bearerTokenPrefix = (authorizationHeader) ? authorizationHeader.split(" ")[0] : '',
				bearerToken = (authorizationHeader) ? authorizationHeader.split(" ")[1] : undefined;

			var _hasBearerTokenPayload = res.bearerTokenPayload;
			var _hasAuthorizationHeader = typeof authorizationHeader !== 'undefined';
			var _authorizationHeaderIsValid = bearerTokenPrefix == 'Bearer' && typeof bearerToken !== 'undefined';

			if (_hasBearerTokenPayload && role == 'authentication') {
				_report('payload found');
				res.signedBearerToken = jsonwebtoken.sign(res.bearerTokenPayload, secretOrPrivateKey, options.sign);
				_report('token signed');
				if (options.autoSendToken) {
					res.status(httpCodes.OK).json({
						signedBearerToken: res.signedBearerToken
					});
					_report('token sent');
				}
			}

			if (_hasAuthorizationHeader && role == 'authorization') {
				_report('authorization header found');
				if (_authorizationHeaderIsValid) {
					_report('token found in authorization header');
					try {
						var _decodedBearerToken = jsonwebtoken.verify(bearerToken, secretOrPrivateKey, options.verify);
						if (isRevokedToken(bearerToken)) {
							_rejectToken(_error('revokedToken', 'Request authorization was previously revoked'));
						} else {
							req.decodedBearerToken = _decodedBearerToken;
							_report('token decoded');
						}
					} catch (error) {
						_rejectToken(error);
					}
				} else _rejectToken(_error('malformedAuthorizationHeader', 'Authorization header is malformed, should be in the form of: Bearer <token>'));
			} else req.isAnonymous = true;

			if (options.debug) {
				console.log(_name + ' called, report:');
				console.log(req.tokenwareReport);
				console.log('\n');
			}
			(req.tokenwareError) ? next(req.tokenwareError): next();
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
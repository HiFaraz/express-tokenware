var rp = require('request-promise'),
	express = require('express'),
	httpCodes = require('http-codes'),
	jsonwebtoken = require('jsonwebtoken'),
	tokenwareConstructor = require('../lib');

var secretKey = 'someSecretKey';

var expiredTestToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoic29tZVVzZXJOYW1lIiwiaWF0IjoxNDUwOTA3Nzk2fQ.E_XpSmwIP2nYJf7ZSUbEAXLqVxirgjVyJHfvpXCEEbM';

var getURL = function (server) {
	return 'http://localhost:' + server.address().port;
};

var customErrorHandlingMiddleware = function (err, req, res, next) {
	res.send(err);
};

describe('given a custom error handler, and', function () {
	describe('given a malformed authorization header, it', function () {
		it('should respond with a specific error message', function (done) {
			var app = express(),
				tokenware = tokenwareConstructor(secretKey, {
					handleErrors: false
				});
			app.use(tokenware);
			app.use(customErrorHandlingMiddleware);

			var server = app.listen(0);
			var check = function (message) {
				expect(message).toEqual('Authorization header is malformed, should be in the form of: Bearer <token>');
				server.close();
				done();
			};
			rp({
					url: getURL(server),
					headers: {
						authorization: 'token ' + expiredTestToken
					},
					resolveWithFullResponse: true,
					json: true
				})
				.then(function (response) {
					check(response.body.message);
				})
				.catch(function (error) {
					check(error.error.error);
				});
		});
	});

	describe('given a proper authorization header, and', function () {
		describe('given an invalid token, it', function () {
			it('should respond with a specific error name', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey, {
						handleErrors: false
					});
				app.use(tokenware);
				app.use(customErrorHandlingMiddleware);

				var server = app.listen(0);
				var check = function (name) {
					expect(name).toEqual('JsonWebTokenError');
					server.close();
					done();
				};
				rp({
						url: getURL(server),
						headers: {
							authorization: 'Bearer INVALID' + expiredTestToken
						},
						resolveWithFullResponse: true,
						json: true
					})
					.then(function (response) {
						check(response.body.name);
					})
					.catch(function (error) {
						check(error.error.error);
					});
			});
		});

		describe('given an expired token, it', function () {
			it('should respond with a specific error name', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey, {
						expiresIn: '1 second',
						handleErrors: false
					});
				app.use(tokenware);
				app.use(customErrorHandlingMiddleware);

				var server = app.listen(0);
				var check = function (name) {
					expect(name).toEqual('TokenExpiredError');
					server.close();
					done();
				};
				rp({
						url: getURL(server),
						headers: {
							authorization: 'Bearer ' + expiredTestToken
						},
						resolveWithFullResponse: true,
						json: true
					})
					.then(function (response) {
						check(response.body.name);
					})
					.catch(function (error) {
						check(error.error.error);
					});
			});
		});

		describe('given an revoked token, it', function () {
			var isRevokenToken = function (token) {
				return token == expiredTestToken;
			};

			it('should respond with a specific error message', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey, {
						handleErrors: false
					}, isRevokenToken);
				app.use(tokenware);
				app.use(customErrorHandlingMiddleware);

				var server = app.listen(0);
				var check = function (message) {
					expect(message).toEqual('Request authorization was previously revoked');
					server.close();
					done();
				};
				rp({
						url: getURL(server),
						headers: {
							authorization: 'Bearer ' + expiredTestToken
						},
						resolveWithFullResponse: true,
						json: true
					})
					.then(function (response) {
						check(response.body.message);
					})
					.catch(function (error) {
						check(error.error.error);
					});
			});
		});
	});
});
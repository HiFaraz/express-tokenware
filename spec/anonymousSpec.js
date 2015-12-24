var rp = require('request-promise'),
	express = require('express'),
	httpCodes = require('http-codes'),
	jsonwebtoken = require('jsonwebtoken'),
	tokenware = require('../lib');

var secretKey = 'someSecretKey';

var expiredTestToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoic29tZVVzZXJOYW1lIiwiaWF0IjoxNDUwOTA3Nzk2fQ.E_XpSmwIP2nYJf7ZSUbEAXLqVxirgjVyJHfvpXCEEbM';

var getURL = function (server) {
	return 'http://localhost:' + server.address().port;
};

var anonymousRequestMiddleware = function (req, res, next) {
	if (req.isAnonymous) res.send('anonymous request accepted');
	else res.send('unauthorized request')
};

describe('given that anonymous requests are allowed, and', function () {
	describe('given no authorization header, it', function () {
		it('should respond with an OK code and send a specific message', function (done) {
			var app = tokenware(secretKey, {
				allowAnonymous: true
			})(express);
			app.get('/', anonymousRequestMiddleware);

			var server = app.listen(0);
			var check = function (statusCode, message) {
				expect(statusCode).toEqual(httpCodes.OK);
				expect(message).toEqual('anonymous request accepted');
				server.close();
				done();
			};
			rp({
					url: getURL(server),
					resolveWithFullResponse: true,
					json: true
				})
				.then(function (response) {
					check(response.statusCode, response.body);
				})
				.catch(function (error) {
					check(error.statusCode, error.error.error);
				});
		});
	});

	describe('given a malformed authorization header, it', function () {
		it('should respond with an OK code and send a specific message', function (done) {
			var app = tokenware(secretKey, {
				allowAnonymous: true
			})(express);
			app.get('/', anonymousRequestMiddleware);

			var server = app.listen(0);
			var check = function (statusCode, message) {
				expect(statusCode).toEqual(httpCodes.OK);
				expect(message).toEqual('anonymous request accepted');
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
					check(response.statusCode, response.body);
				})
				.catch(function (error) {
					check(error.statusCode, error.error.error);
				});
		});
	});

	describe('given a proper authorization header, and', function () {
		describe('given an invalid token, it', function () {
			it('should respond with an OK code and send a specific message', function (done) {
				var app = tokenware(secretKey, {
					allowAnonymous: true
				})(express);
				app.get('/', anonymousRequestMiddleware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.OK);
					expect(message).toEqual('anonymous request accepted');
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
						check(response.statusCode, response.body);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});

		describe('given an expired token, it', function () {
			it('should respond with an OK code and send a specific message', function (done) {
				var app = tokenware(secretKey, {
					expiresIn: '1 second',
					allowAnonymous: true
				})(express);
				app.get('/', anonymousRequestMiddleware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.OK);
					expect(message).toEqual('anonymous request accepted');
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
						check(response.statusCode, response.body);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});

		describe('given an revoked token, it', function () {
			var isRevokedToken = function (token) {
				return token == expiredTestToken;
			};

			it('should respond with an OK code and send a specific message', function (done) {
				var app = tokenware(secretKey, {
					allowAnonymous: true
				}, isRevokedToken)(express);
				app.get('/', anonymousRequestMiddleware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.OK);
					expect(message).toEqual('anonymous request accepted');
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
						check(response.statusCode, response.body);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});
	});
});
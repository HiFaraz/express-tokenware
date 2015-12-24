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

describe('given the internal error handler, and', function () {
	describe('given a malformed authorization header, it', function () {
		it('should respond with a BAD REQUEST code and a specific error message', function (done) {
			var app = express(),
				tokenware = tokenwareConstructor(secretKey);
			app.use(tokenware);

			var server = app.listen(0);
			var check = function (statusCode, message) {
				expect(statusCode).toEqual(httpCodes.BAD_REQUEST);
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
					check(response.statusCode, response);
				})
				.catch(function (error) {
					check(error.statusCode, error.error.error);
				});
		});
	});

	describe('given a proper authorization header, and', function () {
		describe('given an invalid token, it', function () {
			it('should respond with an UNAUTHORIZED code and a specific error message', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey);
				app.use(tokenware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.UNAUTHORIZED);
					expect(message).toEqual('Unauthorized request');
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
						check(response.statusCode, response);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});

		describe('given an expired token, it', function () {
			it('should respond with an UNAUTHORIZED code and a specific error message', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey, {
						expiresIn: '1 second'
					});
				app.use(tokenware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.UNAUTHORIZED);
					expect(message).toEqual('Expired request authorization');
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
						check(response.statusCode, response);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});

		describe('given an revoked token, it', function () {
			var isRevokenToken = function (token) {
				return token == expiredTestToken;
			};

			it('should respond with an UNAUTHORIZED code and a specific error message', function (done) {
				var app = express(),
					tokenware = tokenwareConstructor(secretKey, isRevokenToken);
				app.use(tokenware);

				var server = app.listen(0);
				var check = function (statusCode, message) {
					expect(statusCode).toEqual(httpCodes.UNAUTHORIZED);
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
						check(response.statusCode, response);
					})
					.catch(function (error) {
						check(error.statusCode, error.error.error);
					});
			});
		});
	});
});
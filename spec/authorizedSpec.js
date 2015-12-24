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

describe('given a proper authorization header, and', function () {
	describe('given a valid token, it', function () {
		it('should respond with an OK code and decode the token properly', function (done) {
			var app = express(),
				tokenware = tokenwareConstructor(secretKey);
			app.use(tokenware);
			app.get('/', function (req, res, next) {
				res.send(req.decodedBearerToken);
			});

			var server = app.listen(0);
			var check = function (statusCode, user) {
				expect(statusCode).toEqual(httpCodes.OK);
				expect(user).toEqual('someUserName');
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
					check(response.statusCode, response.body.user);
				})
				.catch(function (error) {
					check(error.statusCode, error.error.error);
				});
		});
	});
});
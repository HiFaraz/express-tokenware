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

describe('given a bearer token payload, it', function () {
	it("should respond with an OK code and a properly coded token", function (done) {
		var app = tokenware(secretKey)(express);
		app.get('/',
			function (req, res, next) {
				res.locals.bearerTokenPayload = {
					user: 'someUserName'
				};
				next();
			}
		);

		var server = app.listen(0);
		var check = function (statusCode, user) {
			expect(statusCode).toEqual(httpCodes.OK);
			expect(user).toEqual('someUserName');
			server.close();
			done();
		};
		rp({
				url: getURL(server),
				json: true,
				resolveWithFullResponse: true
			})
			.then(function (response) {
				check(response.statusCode, jsonwebtoken.verify(response.body.signedBearerToken, secretKey).user);
			})
			.catch(function (error) {
				check(error.statusCode, error.error.error);
			});
	});
});
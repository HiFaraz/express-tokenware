describe('express-tokenware', function () {
	describe('authentication', function () {
		var rp = require('request-promise'),
			express = require('express'),
			httpCodes = require('http-codes'),
			tokenwareConstructor = require('../lib');

		var secretKey = 'someSecretKey',
			tokenwareOptions = {
				expiresIn: 1
			},
			isRevokenToken = function (token) {
				return token == expiredTestToken;
			};

		var expiredTestToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoic29tZVVzZXJOYW1lIiwiaWF0IjoxNDUwOTA3Nzk2fQ.E_XpSmwIP2nYJf7ZSUbEAXLqVxirgjVyJHfvpXCEEbM';

		it("should get a token", function (done) {
			var app = express(),
				tokenware = tokenwareConstructor(secretKey, {
					debug: true
				});
			app.use(tokenware);
			app.get('/',
				function (req, res, next) {
					req.bearerTokenPayload = {
						user: 'someUserName' // the payload can be anything
					};
					next();
				},
				tokenware,
				function (req, res, next) {}
			);
			var server = app.listen(0),
				url = 'http://localhost:' + server.address().port;
			var check = function (statusCode, body) {
				expect(statusCode).toEqual(httpCodes.OK);
				server.close();
				done();
			};
			rp({
					url: url,
					json: true,
					resolveWithFullResponse: true
				})
				.then(function (response) {
					console.log('token received: ' + response.body.signedBearerToken);
					check(response.statusCode, response.body.signedBearerToken);
				})
				.catch(function (error) {
					check(error.statusCode, error.error.error);
				});
		});
	});

	//	describe('authorization', function () {});
});

/* EXAMPLE CODE - TODO DELETE */

//	beforeEach(function () {
//		player = new Player();
//		song = new Song();
//	});
//
//	it("should be able to play a Song", function () {
//		player.play(song);
//		expect(player.currentlyPlayingSong).toEqual(song);
//
//		//demonstrates use of custom matcher
//		expect(player).toBePlaying(song);
//	});
//
//	describe("when song has been paused", function () {
//		beforeEach(function () {
//			player.play(song);
//			player.pause();
//		});
//
//		it("should indicate that the song is currently paused", function () {
//			expect(player.isPlaying).toBeFalsy();
//
//			// demonstrates use of 'not' with a custom matcher
//			expect(player).not.toBePlaying(song);
//		});
//
//		it("should be possible to resume", function () {
//			player.resume();
//			expect(player.isPlaying).toBeTruthy();
//			expect(player.currentlyPlayingSong).toEqual(song);
//		});
//	});
//
//	// demonstrates use of spies to intercept and test method calls
//	it("tells the current song if the user has made it a favorite", function () {
//		spyOn(song, 'persistFavoriteStatus');
//
//		player.play(song);
//		player.makeFavorite();
//
//		expect(song.persistFavoriteStatus).toHaveBeenCalledWith(true);
//	});
//
//	//demonstrates use of expected exceptions
//	describe("#resume", function () {
//		it("should throw an exception if song is already playing", function () {
//			player.play(song);
//
//			expect(function () {
//				player.resume();
//			}).toThrowError("song is already playing");
//		});
//	});
//});
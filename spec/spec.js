describe("express-tokenware", function () {
	var request = require('request'),
		rp = require('request-promise'),
		express = require('express'),
		secretKey = 'someSecretKey',
		tokenwareOptions = {
			expiresIn: 1
		},
		expiredTestToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoic29tZVVzZXJOYW1lIiwiaWF0IjoxNDUwOTA3Nzk2fQ.E_XpSmwIP2nYJf7ZSUbEAXLqVxirgjVyJHfvpXCEEbM',
		isRevokenToken = function (token) {
			return token == expiredTestToken;
		},
		tokenwareConstructor = require('../lib');

	it("should get a token", function () {
		var app = express(),
			tokenware = tokenwareConstructor(secretKey);
		app.use(tokenware.setHeaders);
		app.get('/',
			function (req, res, next) {
				req.bearerTokenPayload = {
					user: 'someUserName' // the payload can be anything
				};
				next();
			},
			tokenware.sign,
			tokenware.send,
			tokenware.errorHandler
		);
		var server = app.listen(0),
			url = 'http://localhost:' + server.address().port;
		var check = function (statusCode, body) {
			expect(statusCode).toEqual(200);
			server.close();
		};
		rp({
				uri: url,
				json: true,
				resolveWithFullResponse: true
			})
			.then(function (response) {
				check(response.statusCode, response.body.signedBearerToken);
			}).catch(function (error) {
				check(error.statusCode, error.error.error);
			});
	});
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
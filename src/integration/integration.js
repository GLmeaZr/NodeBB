'use strict';

require('dotenv').config();
var redis = require('redis');
var client = redis.createClient();
var signature = require('cookie-signature');
var User = require('../user');
var authenticationController = require('../controllers/authentication');
var MongoClient = require('mongodb').MongoClient;
var url = process.env.DATABASE;

var unsignCookie = function (val, secrets) {
	for (var i = 0; i < secrets.length; i++) {
		var result = signature.unsign(val, secrets[i]);

		if (result !== false) {
			return result;
		}
	}

	return false;
};

module.exports = {
	checkSessionFromApp: function (request, cb) {
		if (request.cookies['connect.sid']) {
			client.get('sess:' + unsignCookie(request.cookies['connect.sid'].slice(2), ['db7bb930f08ce2365191466ba0f266ce']),
				function (err, reply) {
					if (err) {
						cb(null);
					} else if (JSON.parse(reply) && JSON.parse(reply).passport && JSON.parse(reply).passport.user) {
						var uid = parseInt(JSON.parse(reply).passport.user, 10);
						User.exists(uid, function (err, value) {
							if (err) {
								cb(null);
							} else if (value) {
								User.getUserData(uid, function (err, user) {
									if (err) {
										cb(null);
									} else if (user) {
										request.cookies['express.sid'] = "";
										request.login({ uid: uid }, function () {
											authenticationController.onSuccessfulLogin(request, uid, function() {
												cb(user);
											});
										});
									} else {
										cb(null);
									}
								});
							} else {
								MongoClient.connect(url, function (err, db) {
									if (err) {
										cb(null);
									} else {
										db.collection(process.env.COLLECTION)
											.findOne({ _id: new (require('mongodb')).ObjectID(JSON.parse(reply).passport.user) },
												{ email: 1, username: 1 }, function (err, user) {
													if (err) {
														cb(null);
													} else if (user) {
														User.create(
															{
																username: user.username,
																email: user.email,
																uid: uid,
															},
															function (err, userCreated) {
																if (err) {
																	cb(null);
																} else {
																	cb(userCreated);
																}
															});
													} else {
														console.log('NOT FOUND');
														cb(null);
													}
													db.close();
												});
									}
								});
							}
						});
					} else {
						cb(null);
					}
				});
		} else {
			cb(null);
		}
	}
};

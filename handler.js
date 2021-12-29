"use strict";

let loginService = require("./api/Login");

exports.login = loginService.login;
exports.logout = loginService.logout;
exports.helloWorld=loginService.helloWorld



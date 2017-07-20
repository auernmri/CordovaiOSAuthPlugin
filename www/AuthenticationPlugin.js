var exec = require('cordova/exec');

exports.authenticate = function(samlRequest, idpUrl, successCallback, errorCallback) {
    exec(successCallback, errorCallback, "AuthenticationPlugin", "authenticate", [samlRequest, idpUrl]);
};
               
exports.validateSession = function(sessionCookieName, sessionTime, successCallback, errorCallback) {
    exec(successCallback, errorCallback, "AuthenticationPlugin", "validateSession", [sessionCookieName, sessionTime]);
};

exports.resetSessionTimestamp = function(graceTime, successCallback, errorCallback) {
    exec(successCallback, errorCallback, "AuthenticationPlugin", "resetSessionTimestamp", [graceTime]);
};

exports.provideCert = function(certStr, passwortStr, successCallback, errorCallback) {
    exec(successCallback, errorCallback, "AuthenticationPlugin", "provideCert", [certStr, passwortStr]);
};

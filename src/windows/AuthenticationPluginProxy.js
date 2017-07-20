
cordova.commandProxy.add("AuthenticationPlugin", {
    authenticate:function (success, error, args) {
        // args[0] = SAML Request
        // args[1] = Idp URL
        var namResponse = AuthenticationComponent.AuthenticationHandler.authenticate(args[0], args[1]);
        if (namResponse != null) {
            success(namResponse);
        } else {
            error('No SAML response received...');
        }
    },
    validateSession:function (success, error, args) {
        // args[0] = session cookie name
        // args[1] = session timeout in minutes
        if (args.length === 0 
            || typeof args[0] !== 'string' || args[0].length === 0
            || typeof args[1] !== 'number' || args[1].length === 0) {

            error('Invalid arguments');
        } else {
            var validationResponse = AuthenticationComponent.AuthenticationHandler.validateSession(args[0], args[1]);
            if (validationResponse != null) {
                success(validationResponse);
            } else {
                error('Unable to perform session validation...');
            }
        }
    },
    resetSessionTimestamp:function (success, error, args) {
        // args[0] = grace time in minutes
        if (args.length === 0 || typeof args[0] !== 'number' || args[0].length === 0) {
            error('Invalid arguments');
        } else {
            var response = AuthenticationComponent.AuthenticationHandler.resetSessionTimestamp(args[0]);
            if (response != null) { 
                success(response);
            } else {
                error('Unable to reset session timestamp');
            }
        }
    }
});

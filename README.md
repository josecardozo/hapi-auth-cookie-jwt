# hapi-auth-cookie-jwt #

This is a [Hapi](http://hapijs.com) JSON Web Token (JWT), authentication plugin. It's based on the project [hapi-auth-jwt](https://github.com/ryanfitz/hapi-auth-jwt), but with the difference that in this plugin, the token is passed through the **cookie** header field.

JSON Web Token authentication requires verifying a signed token. The `'jwt-cookie'` scheme takes the following options:

- `key` - (required) The private key the token was signed with.
- `validateFunc` - (optional) validation and user lookup function with the signature `function(token, callback)` where:
    - `token` - the verified and decoded jwt token
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - an internal error.
        - `isValid` - `true` if the token was valid otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Typically, `credentials` are only
          included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails
          (e.g. with authentication mode `'try'`).

See the example folder for an executable example.

```javascript

var Hapi = require('hapi'),
    jwt = require('jsonwebtoken'),
    server = new Hapi.Server();

server.connection({ port: 8080 });

var accounts = {
    123: {
        id: 123,
        user: 'john',
        fullName: 'John Doe',
        scope: ['a', 'b']
    }
};

var privateKey = 'FCC064A9-204E-4E58-A44B-B545D7FD077Y';

// Use this token to set your cookie header.
// Ex:
// set-cookie/cookie: access_token=<token>
var token = jwt.sign({ accountId: 123 }, privateKey);

var validate = function (decodedToken, callback) {

    var error = null;
    var credentials = accounts[decodedToken.accountId] || {};

    if (!credentials) {
        return callback(error, false, credentials);
    }

    return callback(error, true, credentials)
};

var doLoginHandler = function(request, reply) {
	
	// Do whatever is necessary to check user authenticity
	//...
	// and then set-cookie to the client
	return reply().state('access_token', token);
};

server.register(require('hapi-auth-cookie-jwt'), function (error) {

    server.auth.strategy('token', 'jwt-cookie', {
        key: privateKey,
        validateFunc: validate
    });
    
	// Setting the authentication cookie on login
	server.route({
		method: 'POST',
		path: '/login',
		handler: doLoginHandler
	});

    server.route({
        method: 'GET',
        path: '/',
        handler: function(request, reply) {
            return reply('/ -> ok!');
        },
        config: {
            auth: 'token'
        }
    });

    // With scope requirements
    server.route({
        method: 'GET',
        path: '/withScope',
        handler: function(request, reply) {
            return reply('/withScope -> ok!');
        },
        config: {
            auth: {
                strategy: 'token',
                scope: ['a']
            }
        }
    });
});

server.start();

```
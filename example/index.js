var Hapi = require('hapi');
var hapiAuthJwtCookie = require('../lib/index');
var jwt = require('jsonwebtoken');
var server = new Hapi.Server();

server.connection({
    port: 8080
});

var privateKey = 'YourApplicationPrivateKey';

var accounts = {
    123: {
        id: 123,
        user: 'john',
        fullName: 'John Doe'
    }
};

var token = jwt.sign({
    accountId: 123
}, privateKey);

// use this token to build your web request.  
// You'll need to add it to the headers as 'cookie'.  
// And you will need to prefix it with 'access_token='
console.log('token: ' + token);
console.log('Now, access http://127.0.0.1:8080/tokenRequired');
console.log('      and http://127.0.0.1:8080/noTokenRequired');

var validate = function(decodedToken, callback) {

    console.log(decodedToken); // should be {accountId : 123}.

    if (decodedToken) {
        console.log(decodedToken.accountId.toString());
    }

    var account = accounts[decodedToken.accountId];

    if (!account) {
        return callback(null, false);
    }

    return callback(null, true, account);
};

server.register(hapiAuthJwtCookie, function() {

    server.auth.strategy('token', 'jwt-cookie', {
        key: privateKey,
        validateFunc: validate
    });

    server.route({
        // GET to http://localhost:8080/tokenRequired
        // with cookie request headers set to access_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50SWQiOjEyMywiaWF0IjoxMzkyNTg2NzgwfQ.nZT1lsYoJvudjEYodUdgPR-32NNHk7uSnIHeIHY5se0
        // That is, the text 'access_token=' + the token.
        method: 'GET',
        path: '/tokenRequired',
        config: {
            auth: 'token'
        },
        handler: function(request, reply) {
            var replyObj = {
                text: 'I am a JSON response, and you needed a token to get me.',
                credentials: request.auth.credentials
            };
            reply(replyObj);
        }
    });

    server.route({
        // GET to http://localhost:8080/noTokenRequired
        // This get can be executed without sending any token at all
        method: "GET",
        path: "/noTokenRequired",
        config: {
            auth: false
        },
        handler: function(request, reply) {
            var replyObj = {
                text: 'I am a JSON response, but you did not need a token to get me'
            };
            reply(replyObj);
        }
    });

});

server.start();
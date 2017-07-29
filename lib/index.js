var Boom = require('boom');
var Hoek = require('hoek');
var jwt  = require('jsonwebtoken');

var internals = {};

exports.register = function (server, options, next) {

    server.auth.scheme('jwt-cookie', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing jwt auth strategy options');
    Hoek.assert(options.key, 'Missing required private key in configuration');

    var settings = Hoek.clone(options);

    var scheme = {

        authenticate: function (request, reply) {

            //can request.state be null or undefined? Just in case
            if (!request.state) {
                return reply(Boom.unauthorized(null, 'Access Token'));
            }
    
            var access_token = request.state['access_token'];

            if(!access_token) {
                return reply(Boom.unauthorized(null, 'Access Token'));
            }
    
            if(access_token.split('.').length !== 3) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Access Token'));
            }
    
            jwt.verify(access_token, settings.key, function(err, decoded) {

                if(err && err.message === 'jwt expired') {
                    return reply(Boom.unauthorized('Expired token received for JSON Web Token validation', 'Access Token'));
                } else if (err) {
                    return reply(Boom.unauthorized('Invalid signature received for JSON Web Token validation', 'Access Token'));
                }
    
                if (!settings.validateFunc) {
                    return reply.continue({ credentials: decoded });
                }
    
    
                settings.validateFunc(decoded, function (err, isValid, credentials) {
    
                    credentials = credentials || null;
    
                    if (err) {
                        return reply(err, null, { credentials: credentials });
                    }
    
                    if (!isValid) {
                        return reply(Boom.unauthorized('Invalid token', 'Access Token'), null, { credentials: credentials });
                    }
    
                    if (!credentials || typeof credentials !== 'object') {
                        return reply(Boom.badImplementation('Bad credentials object received for jwt auth validation'), null, { log: { tags: 'credentials' } });
                    }

                    // Ok, you're free to go
                    return reply.continue({ credentials: credentials });
                });
            });
        }
    }
    return scheme;
};
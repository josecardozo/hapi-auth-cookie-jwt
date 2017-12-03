const Boom = require('boom');
const Hoek = require('hoek');
const jwt  = require('jsonwebtoken');

const internals = {};

exports.plugin = {
    register: (server, options) => {
        server.auth.scheme('jwt-cookie', internals.implementation);
    },
    pkg: require('../package.json'),
    name: 'hapi-auth-cookie-jwt'
};

internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing jwt auth strategy options');
    Hoek.assert(options.key, 'Missing required private key in configuration');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: async (request, h) => {

            // can request.state be null or undefined? Just in case
            if (!request.state) {
                return Boom.unauthorized(null, 'Access Token');
            }
    
            const access_token = request.state['access_token'];

            if (!access_token) {
                return Boom.unauthorized(null, 'Access Token');
            }
    
            if (access_token.split('.').length !== 3) {
                return Boom.badRequest('Bad HTTP authentication header format', 'Access Token');
            }

            let decoded = null;
            try {        
                decoded = await jwt.verify(access_token, settings.key);
            } catch (err) {
                if (err.message === 'jwt expired') {
                    return h.unauthenticated(Boom.unauthorized('Expired token received for JSON Web Token validation', 'Access Token'));
                } else {
                    return h.unauthenticated(Boom.unauthorized('Invalid signature received for JSON Web Token validation', 'Access Token'));
                }
            }

            if (!settings.validateFunc) {
                return h.authenticated({ credentials: decoded });
            }
    
            return settings.validateFunc(decoded, function (err, isValid, credentials) {
                credentials = credentials || null;

                if (err) {
                    return Boom.badImplementation(err, null, { credentials: credentials });
                }

                if (!isValid) {
                    return h.unauthenticated(Boom.unauthorized('Invalid token', 'Access Token', null, { credentials: credentials }));
                }

                if (!credentials || typeof credentials !== 'object') {
                    return Boom.badImplementation('Bad credentials object received for jwt auth validation', null, { log: { tags: 'credentials' } });
                }

                // Ok, you're free to go
                return h.authenticated({ credentials: credentials });
            });
        }
    }
    return scheme;
};

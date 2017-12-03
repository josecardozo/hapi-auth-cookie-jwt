const Jwt  = require('jsonwebtoken');
const Boom = require('boom');
const Hapi = require('hapi');
const Lab  = require('lab');

const lab = exports.lab = Lab.script();
const expect = require('chai').expect;
const describe = lab.describe;
const before = lab.before;
const it = lab.it;

const util = require('util');

describe('Token', function () {

    const privateKey = '8F6DA9E8-4A86-4B3E-ABBB-199E17EE5B70';

    const tokenHeader = (username, options) => {
        options = options || {};
        return 'access_token=' + Jwt.sign({username}, privateKey, options);
    };

    const loadUser = (decodedToken, callback) => {
        const username = decodedToken.username;

        if (username === 'johndoe') {
            return callback(null, true, {
                user: 'johndoe',
                scope: ['a']
            });
        } else if (username === 'jane') {
            return callback(Boom.badImplementation());
        } else if (username === 'invalid1') {
           return callback(null, true, 'bad');
        } else if (username === 'nullman') {
           return callback(null, true, null);
        }
        return callback(null, false);
    };

    const tokenHandler = (request, h) => {
        return 'ok';
    };

    const doubleHandler = async (request, h) => {
        const options = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('johndoe')
            },
            credentials: request.auth.credentials
        };
        const response = await server.inject(options);
        const payload = response.payload;
        return payload;
    };

    const server = new Hapi.Server({ debug: false });

    before(async () => {

        const error = await server.register({plugin: require('../')});
        expect(error).to.not.exist;
        server.auth.strategy('default', 'jwt-cookie', { key: privateKey,  validateFunc: loadUser });
        server.auth.default({
            mode: 'required',
            strategy: 'default'
        });

        server.route([
            {
                method: 'POST',
                path: '/token',
                handler: tokenHandler,
                options: {
                    auth: 'default'
                }
            },
            {
                method: 'POST',
                path: '/tokenOptional',
                handler: tokenHandler,
                options: {
                    auth: {
                        mode: 'optional'
                    }
                }
            },
            {
                method: 'POST',
                path: '/tokenScope',
                handler: tokenHandler,
                options: {
                    auth: {
                        scope: 'x'
                    }
                }
            },
            {
                method: 'POST',
                path: '/tokenArrayScope',
                handler: tokenHandler,
                options: {
                    auth: {
                        scope: ['x', 'y']
                    }
                }
            },
            {
                method: 'POST',
                path: '/tokenArrayScopeA',
                handler: tokenHandler,
                options: {
                    auth: {
                        scope: ['x', 'y', 'a']
                    }
                }
            },
            {
                method: 'POST',
                path: '/double',
                handler: doubleHandler
            }
        ]);
    });

    it('Returns a reply on successful auth', async () => {
        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.result).to.equal('ok');
    });

    it('Returns decoded token when no validation function is set', async () => {

        const handler = (request, h) => {
            expect(request.auth.isAuthenticated).to.equal(true);
            expect(request.auth.credentials).to.exist;
            return 'ok';
        };

        const server = new Hapi.Server({ debug: false });

        const error = await server.register({plugin: require('../')});
        expect(error).to.not.exist;
        server.auth.strategy('default', 'jwt-cookie', { key: privateKey });
        server.auth.default({
            mode: 'required',
            strategy: 'default'
        });
        server.route([
            {
                method: 'POST',
                path: '/token',
                handler: handler,
                config: {
                    auth: 'default'
                }
            }
        ]);

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.result).to.equal('ok');
    });

    it('Returns an error on wrong scheme', async () => {
        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: 'JUST_A_EXAMPLE=BLAH'
            }
        };

        const res = await server.inject(request);
        expect(res.statusCode).to.equal(401);
    });

    it('Returns a reply on successful double auth', async () => {

        const request = {
            method: 'POST',
            url: '/double',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.result).to.equal('ok');
    });

    it('Returns a reply on failed optional auth', async () => {

        const request = {
            method: 'POST',
            url: '/tokenOptional'
        };

        const res = await server.inject(request);
        expect(res.result).to.equal('ok');
    });

    it('Returns an error with expired token', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('johndoe', { expiresIn: -10 })
            }
        };

        const res = await server.inject(request);
        expect(res.result.message).to.equal('Expired token received for JSON Web Token validation');
        expect(res.statusCode).to.equal(401);
    });

    it('Returns an error with invalid token', async () => {
        
        const token = tokenHeader('johndoe') + '15643287619';
        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: token
            }
        };

        const res = await server.inject(request);
        expect(res.result.message).to.equal('Invalid signature received for JSON Web Token validation');
        expect(res.statusCode).to.equal(401);
    });

    it('Returns an error on bad header format', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: 'Bearer'
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
    });

    it('Returns an error on bad header format', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: 'bearer'
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
    });

    it('Returns an error on bad header internal syntax', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: 'bearer 123'
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
    });

    it('Returns an error on unknown user', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('doe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(401);
    });

    it('Returns an error on internal user lookup error', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('jane')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
    });

    it('Returns an error on non-object credentials error', async () => {

        const request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('invalid1') } };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
    });

    // ??
    it('Returns an error on null credentials error', async () => {

        const request = {
            method: 'POST',
            url: '/token',
            headers: {
                cookie: tokenHeader('nullman')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
    });

    it('Returns an error on insufficient scope', async () => {

        const request = {
            method: 'POST',
            url: '/tokenScope',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(403);
    });

    it('Returns an error on insufficient scope specified as an array', async () => {

        const request = {
            method: 'POST',
            url: '/tokenArrayScope',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(403);
    });

    it('Authenticates scope specified as an array', async () => {

        const request = {
            method: 'POST',
            url: '/tokenArrayScopeA',
            headers: {
                cookie: tokenHeader('johndoe')
            }
        };

        const res = await server.inject(request);
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
    });

    it('Cannot add a route that has payload validation required', async () => {

        const fn = function () {
            server.route({ method: 'POST', path: '/tokenPayload', handler: tokenHandler, options: { auth: { mode: 'required', payload: 'required' } } });
        };

        expect(fn).to.throw(Error);
    });
});

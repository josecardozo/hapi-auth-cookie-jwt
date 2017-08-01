var Jwt  = require('jsonwebtoken');
var Boom = require('boom');
var Hapi = require('hapi');
var Lab  = require('lab');

var lab = exports.lab = Lab.script();
var expect = require('chai').expect;
var describe = lab.describe;
var before = lab.before;
var it = lab.it;

var util = require('util');

describe('Token', function () {

    var privateKey = '8F6DA9E8-4A86-4B3E-ABBB-199E17EE5B70';

    var tokenHeader = function (username, options) {

        options = options || {};
        return 'access_token=' + Jwt.sign({username : username}, privateKey, options);
    };

    var loadUser = function (decodedToken, callback) {
        
        var username = decodedToken.username;

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

    var tokenHandler = function (request, reply) {

        reply('ok');
    };

    var doubleHandler = function (request, reply) {

        var options = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('johndoe') }, credentials: request.auth.credentials };
        server.inject(options, function (res) {

            reply(res.result);
        });
    };

    var server = new Hapi.Server({ debug: false });
    server.connection();

    before(function (done) {

        server.register(require('../'), function (err) {

            expect(err).to.not.exist;
            server.auth.strategy('default', 'jwt-cookie', 'required', { key: privateKey,  validateFunc: loadUser });

            server.route([
                { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } },
                { method: 'POST', path: '/tokenOptional', handler: tokenHandler, config: { auth: { mode: 'optional' } } },
                { method: 'POST', path: '/tokenScope', handler: tokenHandler, config: { auth: { scope: 'x' } } },
                { method: 'POST', path: '/tokenArrayScope', handler: tokenHandler, config: { auth: { scope: ['x', 'y'] } } },
                { method: 'POST', path: '/tokenArrayScopeA', handler: tokenHandler, config: { auth: { scope: ['x', 'y', 'a'] } } },
                { method: 'POST', path: '/double', handler: doubleHandler }
            ]);
            done();
        });
    });

    it('Returns a reply on successful auth', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('johndoe') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('Returns decoded token when no validation function is set', function (done) {

        var handler = function (request, reply) {
            expect(request.auth.isAuthenticated).to.equal(true);
            expect(request.auth.credentials).to.exist;
            reply('ok');
        };

        var server = new Hapi.Server({ debug: false });

        server.connection();
        server.register(require('../'), function (err) {
            
            expect(err).to.not.exist;
            server.auth.strategy('default', 'jwt-cookie', 'required', { key: privateKey });

            server.route([
                { method: 'POST', path: '/token', handler: handler, config: { auth: 'default' } }
            ]);

            var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('johndoe') } };

            server.inject(request, function (res) {

                expect(res.result).to.exist;
                expect(res.result).to.equal('ok');
                done();
            });
        });
    });

    it('Returns an error on wrong scheme', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: 'JUST_A_EXAMPLE=BLAH' } };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('Returns a reply on successful double auth', function (done) {

        var request = { method: 'POST', url: '/double', headers: { cookie: tokenHeader('johndoe') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('Returns a reply on failed optional auth', function (done) {

        var request = { method: 'POST', url: '/tokenOptional' };

        server.inject(request, function (res) {

            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('Returns an error with expired token', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('johndoe', { expiresIn: -10 }) } };

        server.inject(request, function (res) {
            expect(res.result.message).to.equal('Expired token received for JSON Web Token validation');
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('Returns an error with invalid token', function (done) {
        
        var token = tokenHeader('johndoe') + '15643287619';
        var request = { method: 'POST', url: '/token', headers: { cookie: token } };

        server.inject(request, function (res) {
            expect(res.result.message).to.equal('Invalid signature received for JSON Web Token validation');
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('Returns an error on bad header format', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: 'Bearer' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });

    it('Returns an error on bad header format', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: 'bearer' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });

    it('Returns an error on bad header internal syntax', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: 'bearer 123' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });

    it('Returns an error on unknown user', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('doe') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('Returns an error on internal user lookup error', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('jane') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('Returns an error on non-object credentials error', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('invalid1') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    // ??
    it('Returns an error on null credentials error', function (done) {

        var request = { method: 'POST', url: '/token', headers: { cookie: tokenHeader('nullman') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('Returns an error on insufficient scope', function (done) {

        var request = { method: 'POST', url: '/tokenScope', headers: { cookie: tokenHeader('johndoe') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('Returns an error on insufficient scope specified as an array', function (done) {

        var request = { method: 'POST', url: '/tokenArrayScope', headers: { cookie: tokenHeader('johndoe') } };

            server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('Authenticates scope specified as an array', function (done) {

        var request = { method: 'POST', url: '/tokenArrayScopeA', headers: { cookie: tokenHeader('johndoe') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(200);
            done();
        });
    });

    it('Cannot add a route that has payload validation required', function (done) {

        var fn = function () {

            server.route({ method: 'POST', path: '/tokenPayload', handler: tokenHandler, config: { auth: { mode: 'required', payload: 'required' } } });
        };

        expect(fn).to.throw(Error);
        done();
    });
});
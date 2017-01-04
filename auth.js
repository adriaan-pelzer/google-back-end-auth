const crypto = require ( 'crypto' );
const R = require ( 'ramda' );
const request = require ( 'request' );
const url = require ( 'url' );

const getGoogleCerts = ( kid, cb ) => {
    request ( {
        uri: 'https://www.googleapis.com/oauth2/v1/certs'
    }, ( error, response, body ) => {
        if ( error && response.statusCode !== 200 ) {
            return cb ( error || 'error while retrieving google certs' );
        }

        cb ( null, JSON.parse ( body )[kid] );
    } );
};

const google = require ( 'google-id-token' ), parser = new google ( { getKeys: getGoogleCerts } );

module.exports.sign = ( client_id, client_secret, path, method, body, bin ) => {
    const hash = crypto.createHash ( 'sha256' );
    const Path = url.parse ( path.match ( /^http/ ) ? path : ( 'http://dummy-base-url.com' + path ) ).pathName;
    const Body = body && ( R.type ( body ) === 'String' ? body : JSON.stringify ( body ) );
    const stringToSign = Body ?
        `${client_secret}${client_id}${Path}${method}${Body}` :
        `${client_secret}${client_id}${Path}${method}`;

    hash.update ( bin ? stringToSign : new Buffer ( stringToSign ) );

    return hash.digest ( 'hex' );
};

module.exports.verifySig = ( client_id, client_secret, path, method, sig, body ) => {
    return module.exports.sign ( client_id, client_secret, path, method, body, true ) === sig ||
        module.exports.sign ( client_id, client_secret, path, method, body, false ) === sig;
};

module.exports.verifyToken = ( client_id, id_token, callback ) => {
    parser.decode ( id_token, ( error, token ) => {
        if ( error ) {
            return callback ( 'invalid token' );
        }

        if ( token.isExpired ) {
            return callback ( 'expired' );
        }

        if ( ! token.isAuthentic ) {
            return callback ( 'not authentic' );
        }

        if ( token.data.aud !== [ client_id, 'apps', 'googleusercontent', 'com' ].join ( '.' ) ) {
            return callback ( 'wrong app id' );
        }

        return callback ( null, R.pick ( [ 'email', 'iat', 'exp', 'name', 'given_name', 'family_name', 'locale' ], token.data ) );
    } );
};

module.exports.signRequest = ( config, req ) => {
    return R.merge ( req, {
        qs: R.merge ( req.qs || {}, {
            sig: module.exports.sign ( config.client_id, config.client_secret, req.url, req.method.toUpperCase (), null, true )
        } )
    } );
};

module.exports.verifyRequest = ( config, req, callback ) => {
    var matchWhitelist = function ( email ) {
        if ( R.type ( config.whitelist ) !== 'Array' ) {
            return false;
        }

        return R.reduce ( ( match, rule ) => {
            if ( match ) {
                return true;
            }

            if ( R.type ( rule ) === 'RegExp' ) {
                return rule.test ( email );
            }

            if ( R.type ( rule ) === 'String' ) {
                return rule.toLowerCase () === email.toLowerCase ();
            }

            return false;
        }, false, config.whitelist );
    };

    if ( R.type ( req.query.id_token ) === 'String' ) {
        return module.exports.verifyToken ( config.client_id, req.query.id_token, ( error, token ) => {
            if ( error ) {
                return callback ( error );
            }

            if ( ! matchWhitelist ( token.email ) ) {
                return callback ( 'not authorised' );
            }

            return callback ( null, {
                type: 'id_token',
                userData: token
            } );
        } );
    }

    if ( R.type ( req.query.sig ) === 'String' ) {
        if ( module.exports.verifySig ( config.client_id, config.client_secret, req.url, req.route.method, req.query.sig ) ) {
            return callback ( null, { type: 'sig' } );
        }

        return callback ( 'signature verification failed' );
    }

    if ( config.enforce ) {
        return callback ( 'authentication required' );
    }

    return callback ( null, { type: 'noAuth' } );
};

if ( ! module.parent ) {
    const ranChar = ( start, count ) => {
        if ( start.length < count ) {
            return ranChar ( ( start + Math.random ().toString ( 36 ) ), count );
        }

        return start.substring ( 0, count );
    };

    const test = ( round ) => {
        const client_id = ranChar ( '', 7 );
        const client_secret = ranChar ( '', 7 );
        const method = ranChar ( '', 4 );
        const body = Math.random () < 0.5 ? null : ranChar ( '', 2000 );
        const path = [ ranChar ( '', 20 ), ranChar ( '', 20 ) ].join ( '?' );

        return [ round, client_id, client_secret, method, path, module.exports.verifySig ( client_id, client_secret, path, method, module.exports.sign ( client_id, client_secret, path, method, body, ( Math.random () < 0.5 ) ), body ) ];
    };

    R.forEach ( ( out ) => {
        console.log ( `Test round ${out[0]}` );
        if ( out[5] ) {
            console.log ( 'Success' );
        } else {
            console.log ( '*** ERROR ***' );
            console.log ( `client_id: ${out[1]}` );
            console.log ( `client_secret: ${out[2]}` );
            console.log ( `method: ${out[3]}` );
            console.log ( `path: ${out[4]}` );
        }
    }, R.map ( test, R.range ( 0, 100 ) ) );
}

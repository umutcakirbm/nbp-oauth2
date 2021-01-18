const rand = require('csprng');
const unirand = require('unirand');
const bcrypt = require('bcrypt');
const redisAdapter = require('./redis-adapter');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

class NbpOAuth2 {

    jwtSignKey;
    scopes = [];
    mongoUserSchema;
    mongoUsernameField;
    mongoPasswordField;
    mongoPayloadFields;
    mongoDBConnected = false;

    constructor({ redisHost, redisPort, mongoDBSettings, jwtSignKey, scopes }) {
        this.redisManager = redisAdapter({ host: redisHost, port: redisPort });
        if (mongoDBSettings) {
            this.mongoUserSchema = mongoDBSettings.schema;
            this.mongoUsernameField = mongoDBSettings.usernameField;
            this.mongoPasswordField = mongoDBSettings.passwordField;
            this.mongoPayloadFields = mongoDBSettings.payloadFields;
            if (mongoose.connection.readyState === 0 && !mongoDBSettings.connectionString) {
                throw new Error('mongodb_connection_not_found');
            } else if (mongoDBSettings.connectionString) {
                mongoose.connect(mongoDBSettings.connectionString, { useNewUrlParser: true, useUnifiedTopology: true });
            }
            this.mongoDBConnected = true;
        }
        this.jwtSignKey = jwtSignKey;
        this.scopes = scopes || this.scopes;
    }

    async saveToMongoDB({ schema, payload }) {
        const tmp = new mongoose.Schema({}, { strict: false });
        const Tmp = mongoose.model(schema, tmp);
        const data = new Tmp(payload);
        await data.save();
    }

    async saveClient ({ client_id, client_secret }) {
        if (!this.mongoDBConnected) {
            this.redisManager.set('nbp_auth_client_' + client_id, client_secret);
        } else {
            await this.saveToMongoDB({ schema: 'nbp_auth_clients', payload: {client_id, client_secret }});
        }
    }

    async checkClient ({ client_id }) {
        const client = await this.redisManager.get('nbp_auth_client_' + client_id);
        return !!client;
    }

    async authorize ({ response_type, client_id, redirect_uri, scope, state }) {
        if (scope && this.scopes.indexOf(scope) === -1) {
            throw new Error('invalid_scope');
        }
        if (!(await this.checkClient({ client_id }))) {
            throw new Error('invalid_client');
        }
        const expiresIn = 15 * 1000; // 15 seconds
        const code = NbpOAuth2.AuthorizationCode();
        const token = NbpOAuth2.AuthorizationToken({
            payload: { redirect_uri, scope, state },
            jwtSignKey: this.jwtSignKey,
            expiresIn: '3600s',
            algorithm: 'HS256',
            client_id
        });
        if (response_type === 'code') {
            this.saveAuthorizationCode({ code, client_id, redirect_uri, scope, state, expiresIn });
            return redirect_uri + '?code=' + code + '&expires_in=' + expiresIn
                + (scope ? ('&scope=' + scope) : '')
                + (state ? ('&state=' + state) : '');
        } else if (response_type === 'token') {
            return redirect_uri + '#access_token=' + token + '&expires_in=' + expiresIn
                + (scope ? ('&scope=' + scope) : '')
                + (state ? ('&state=' + state) : '');
        } else if (response_type === 'code_and_token') {
            this.saveAuthorizationCode({ code, client_id, redirect_uri, scope, state, expiresIn });
            return redirect_uri + '?code=' + code + (state ? ('&state=' + state) : '')
                + '#access_token=' + token
                + '&expires_in=' + expiresIn
                + (scope ? ('&scope=' + scope) : '');
        } else {
            throw new Error('unsupported_response_type');
        }
    }
    
    saveAuthorizationCode({ code, client_id, redirect_uri, scope, state, expiresIn }) {
        this.redisManager.set('nbp_auth_code_' + code, { client_id, redirect_uri, scope, state, expiresIn });
    }


}

NbpOAuth2.AuthorizationToken = ({ payload, jwtSignKey, expiresIn, algorithm, client_id  }) => {
    return jwt.sign(payload, jwtSignKey, { expiresIn, algorithm, issuer: client_id });
}

NbpOAuth2.AuthorizationCode = () => {
    return unirand.uid('shortuuid').random();
}

NbpOAuth2.ClientCredentials = () => {
    const salt = rand(150, 30);
    const uuid = unirand.uid('snowflake').random();
    const client_secret = bcrypt.hashSync(uuid + salt, 9);
    return {
        client_id: uuid,
        client_secret
    }
}

const test = async () => {
    const x = NbpOAuth2.ClientCredentials();
    const auth = new NbpOAuth2({
        redisHost: 'localhost',
        redisPort: 6379,
        mongoDBSettings: {
            connectionString: 'mongodb://localhost:27017/nbp-oauth2-test?retryWrites=true&w=majority',
            schema: 'User',
            payloadFields: ['_id'],
            usernameField: 'email',
            passwordField: 'password'
        },
        jwtSignKey: 'TEST',
        scopes: ['umutcakir.fullaccess', 'umutcakir.readonly']
    });

    await auth.saveClient(x);
    
    const redirectUri = await auth.authorize({
        response_type: 'code_and_token',
        client_id: x.client_id,
        redirect_uri: 'https://cb.umutcakir.com/test',
        scope: 'umutcakir.fullaccess',
        state: 'active'
    });
    console.log(redirectUri);
}
test();
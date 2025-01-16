/*
 * Copyright (C) 2024-present Puter Technologies Inc.
 *
 * This file is part of Puter.
 *
 * Puter is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
"use strict"
const express = require('express');
const router = new express.Router();
const {get_taskbar_items, get_user, body_parser_error_handler } = require('../helpers');
const config = require('../config');
const axios = require('axios'); // Add this line
const jwt = require('jsonwebtoken'); // Add this line
const fs = require('fs'); // Add this line at the top
const bcrypt = require('bcrypt')
const { v4: uuidv4 } = require('uuid');
const { Context } = require('../util/context');
const { DB_WRITE } = require('../services/database/consts');

const keycloak = {
    clientId: 'Puter',
    clientSecret: 'RlPL4mR69umkOxqhudw1mdtS9vqq8TAf',
    realm: 'RealmOne',
    authServerUrl: 'http://localhost:8080',
    redirectUri: 'http://puter.localhost:4100/login' // Fixed the redirectUri
};

const complete_ = async ({ req, res, user }) => {
    const svc_auth = req.services.get('auth');
    const { token } = await svc_auth.create_session_token(user, { req });

    res.cookie(config.cookie_name, token, {
        sameSite: 'none',
        secure: true,
        httpOnly: true,
    });

    // send response
    console.log('200 response?');
    return res.send({
        proceed: true,
        next_step: 'complete',
        token: token,
        user:{
            username: user.username,
            uuid: user.uuid,
            email: user.email,
            email_confirmed: user.email_confirmed,
            is_temp: (user.password === null && user.email === null),
        }
    })
};

// -----------------------------------------------------------------------//
// POST /login/keycloak
// -----------------------------------------------------------------------//
router.post('/login/keycloak', express.json(), body_parser_error_handler, async (req, res, next) => {
    if(require('../helpers').subdomain(req) !== 'api' && require('../helpers').subdomain(req) !== '')
        next();

    const { code } = req.body;
    if (!code) {
        return res.status(400).send('Authorization code is required.');
    }

    try {
        // Exchange authorization code for tokens
        const tokenResponse = await axios.post(
            `${keycloak.authServerUrl}/realms/${keycloak.realm}/protocol/openid-connect/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: keycloak.clientId,
                client_secret: keycloak.clientSecret,
                code: code,
                redirect_uri: keycloak.redirectUri
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        // Token response (contains access_token, refresh_token, etc.)
        const tokens = tokenResponse.data;

        // Log the entire tokens object
        //console.info('Token Response:', tokens);

        // Decode the id_token to retrieve its payload
        const idTokenPayload = jwt.decode(tokens.id_token);
        //console.info('ID Token Payload:', idTokenPayload);
        //console.info('ID Token Payload:', idTokenPayload);
        //console.info('ID Token Payload:', idTokenPayload);

        
        const hashedSub = await bcrypt.hash(idTokenPayload.sub, 10);
        
        const temp_body = JSON.stringify({
            username: idTokenPayload.preferred_username,
            referral_code: null,
            email: idTokenPayload.email,
            password: hashedSub,
            referrer: null,
            send_confirmation_code: false,
            p102xyzname:null,
        })
        if(false){} //TODO: implemnt login later
        else{
            
            // this handles new user registration
            const db = req.services.get('database').get(DB_WRITE, 'auth');
            const svc_auth = Context.get('services').get('auth');
            const svc_authAudit = Context.get('services').get('auth-audit');
            svc_authAudit.record({
                requester: Context.get('requester'),
                action: `signup:real`,
                body: temp_body,
            });
            
            // check bot trap, if `p102xyzname` is anything but an empty string it means
            // that a bot has filled the form
            // doesn't apply to temp users
            
            // send event
            
            async function emitAsync(eventName, data) {
                const listeners = process.listeners(eventName);
                
                if (listeners.length === 0) {
                    return data;
                }
                
                await Promise.all(listeners.map(listener => listener(data)));
                return data;
            }

            let event = {
                allow: true,
                ip: req.headers?.['x-forwarded-for'] ||
                    req.connection?.remoteAddress,
                user_agent: req.headers?.['user-agent'],
                body: temp_body,
            };

            const MAX_WAIT = 5 * 1000;
            await Promise.race([
                emitAsync('puter.signup', event),
                new Promise(resolve => setTimeout(() => resolve(), MAX_WAIT)),
            ])
            /*
            if ( req.body.is_temp && req.cookies[config.cookie_name] ) {
                //to move this to the if above 
                const { user, token } = await svc_auth.check_session(
                    req.cookies[config.cookie_name]
                );
                res.cookie(config.cookie_name, token, {
                    sameSite: 'none',
                    secure: true,
                    httpOnly: true,
                });
                // const decoded = await jwt.verify(token, config.jwt_secret);
                // const user = await get_user({ uuid: decoded.uuid });
                if ( user ) {
                    return res.send({
                        token: token,
                        user: {
                            username: user.username,
                            uuid: user.uuid,
                            email: user.email,
                            email_confirmed: user.email_confirmed,
                            requires_email_confirmation: user.requires_email_confirmation,
                            is_temp: (user.password === null && user.email === null),
                            taskbar_items: await get_taskbar_items(user),
                        }
                    });
                }
            }*/
            
            req.body.username = idTokenPayload.preferred_username;
            req.body.email = idTokenPayload.email;
            req.body.password = hashedSub;
            req.body.send_confirmation_code =false;
            const svc_cleanEmail = req.services.get('clean-email');
            const clean_email = svc_cleanEmail.clean(req.body.email);
            const user_uuid = uuidv4();
            const email_confirm_token = uuidv4();
            let insert_res;
            let email_confirm_code = Math.floor(100000 + Math.random() * 900000);

            const audit_metadata = {
                ip: req.connection.remoteAddress,
                ip_fwd: req.headers['x-forwarded-for'],
                user_agent: req.headers['user-agent'],
                origin: req.headers['origin'],
                server: config.server_id,
            };
            
            insert_res = await db.write(
                `INSERT INTO user
                (
                    username, email, clean_email, password, uuid, referrer, 
                    email_confirm_code, email_confirm_token, free_storage, 
                    referred_by, audit_metadata, signup_ip, signup_ip_forwarded, 
                    signup_user_agent, signup_origin, signup_server
                ) 
                VALUES 
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    // username
                    req.body.username,
                    // email
                    req.body.email,
                    // normalized email
                    clean_email,
                    // password aka the sub
                    req.body.password,
                    // uuid
                    user_uuid,
                    // referrer
                    null,
                    // email_confirm_code
                    email_confirm_code,
                    // email_confirm_token
                    email_confirm_token,
                    // free_storage
                    1024*1024*500,
                    // referred_by
                    null,
                    // audit_metadata
                    JSON.stringify(audit_metadata),
                    // signup_ip
                    req.connection.remoteAddress ?? null,
                    // signup_ip_fwd
                    req.headers['x-forwarded-for'] ?? null,
                    // signup_user_agent
                    req.headers['user-agent'] ?? null,
                    // signup_origin
                    req.headers['origin'] ?? null,
                    // signup_server
                    config.server_id ?? null,
                ]
            );
            
            // record activity
            db.write(
                'UPDATE `user` SET `last_activity_ts` = now() WHERE id=? LIMIT 1',
                [insert_res.insertId]
            );
            
            // TODO: cache group id
            const svc_group = req.services.get('group');
            await svc_group.add_users({
                uid: config.default_user_group,
                users: [idTokenPayload.preferred_username]
            });
            const user_id =insert_res.insertId;
            
            const [user] = await db.pread(
                'SELECT * FROM `user` WHERE `id` = ? LIMIT 1',
                [user_id]
            );
            
            // create token for login
            const { token } = await svc_auth.create_session_token(user, {
                req,
            });

            // generate default fsentries
            const svc_user = Context.get('services').get('user');
            await svc_user.generate_default_fsentries({ user });
          
            //set cookie
            
            res.cookie(config.cookie_name, token, {
                sameSite: 'none',
                secure: true,
                httpOnly: true,
            });
            
            
            // add to mailchimp
            
            const svc_event = Context.get('services').get('event');
            svc_event.emit('user.save_account', { user });
            
            let referral_code = null;
            // return results
            return res.send({
                token: token,
                user:{
                    username: user.username,
                    uuid: user.uuid,
                    email: user.email,
                    email_confirmed: user.email_confirmed,
                    requires_email_confirmation: user.requires_email_confirmation,
                    is_temp: (user.password === null && user.email === null),
                    taskbar_items: await get_taskbar_items(user),
                    referral_code,
                }
            })
                 
        }

        
        return await complete_({ req, res, user });
        
    } catch (error) {
        console.error('Error during Keycloak login:', error);
        return res.status(500).send('Internal Server Error');
    }
});

// -----------------------------------------------------------------------//
// POST /file
// -----------------------------------------------------------------------//
router.post('/login', express.json(), body_parser_error_handler, async (req, res, next)=>{
    // either api. subdomain or no subdomain
    if(require('../helpers').subdomain(req) !== 'api' && require('../helpers').subdomain(req) !== '')
        next();

    // modules
    const bcrypt = require('bcrypt')
    const validator = require('validator')

    // either username or email must be provided
    if(!req.body.username && !req.body.email)
        return res.status(400).send('Username or email is required.')
    // password is required
    else if(!req.body.password)
        return res.status(400).send('Password is required.')
    // password must be a string
    else if (typeof req.body.password !== 'string' && !(req.body.password instanceof String))
        return res.status(400).send('Password must be a string.')
    // if password is too short it's invalid, no need to do a db lookup
    else if(req.body.password.length < config.min_pass_length)
        return res.status(400).send('Invalid password.')
    // username, if present, must be a string
    else if (req.body.username && typeof req.body.username !== 'string' && !(req.body.username instanceof String))
        return res.status(400).send('username must be a string.')
    // if username doesn't pass regex test it's invalid anyway, no need to do DB lookup
    else if(req.body.username && !req.body.username.match(config.username_regex))
        return res.status(400).send('Invalid username.')
    // email, if present, must be a string
    else if (req.body.email && typeof req.body.email !== 'string' && !(req.body.email instanceof String))
        return res.status(400).send('email must be a string.')
    // if email is invalid, no need to do DB lookup anyway
    else if(req.body.email && !validator.isEmail(req.body.email))
        return res.status(400).send('Invalid email.')

    const svc_edgeRateLimit = req.services.get('edge-rate-limit');
    if ( ! svc_edgeRateLimit.check('login') ) {
        return res.status(429).send('Too many requests.');
    }

    try{
        let user;
        // log in using username
        if(req.body.username){
            user = await get_user({ username: req.body.username, cached: false });
            if(!user)
                return res.status(400).send('Username not found.')
        }
        // log in using email
        else if(validator.isEmail(req.body.email)){
            user = await get_user({ email: req.body.email, cached: false });
            if(!user)
                return res.status(400).send('Email not found.')
        }
        // is user suspended?
        if(user.suspended)
            return res.status(401).send('This account is suspended.')
        // pseudo user?
        // todo make this better, maybe ask them to create an account or send them an activation link
        if(user.password === null)
            return res.status(400).send('Incorrect password.')
        // check password
        if(await bcrypt.compare(req.body.password, user.password)){
            // We create a JWT that can ONLY be used on the endpoint that
            // accepts the OTP code.
            if ( user.otp_enabled ) {
                const svc_token = req.services.get('token');
                const otp_jwt_token = svc_token.sign('otp', {
                    user_uid: user.uuid,
                }, { expiresIn: '5m' });

                return res.status(202).send({
                    proceed: true,
                    next_step: 'otp',
                    otp_jwt_token: otp_jwt_token,
                });
            }

            console.log('UMM?');
            return await complete_({ req, res, user });
        }else{
            return res.status(400).send('Incorrect password.')
        }
    }catch(e){
        console.error(e);
        return res.status(400).send(e);
    }

})

router.post('/login/otp', express.json(), body_parser_error_handler, async (req, res, next) => {
    // either api. subdomain or no subdomain
    if(require('../helpers').subdomain(req) !== 'api' && require('../helpers').subdomain(req) !== '')
        next();

    const svc_edgeRateLimit = req.services.get('edge-rate-limit');
    if ( ! svc_edgeRateLimit.check('login-otp') ) {
        return res.status(429).send('Too many requests.');
    }

    if ( ! req.body.token ) {
        return res.status(400).send('token is required.');
    }

    if ( ! req.body.code ) {
        return res.status(400).send('code is required.');
    }

    const svc_token = req.services.get('token');
    let decoded; try {
        decoded = svc_token.verify('otp', req.body.token);
    } catch ( e ) {
        return res.status(400).send('Invalid token.');
    }

    if ( ! decoded.user_uid ) {
        return res.status(400).send('Invalid token.');
    }

    const user = await get_user({ uuid: decoded.user_uid, cached: false });
    if ( ! user ) {
        return res.status(400).send('User not found.');
    }

    const svc_otp = req.services.get('otp');
    if ( ! svc_otp.verify(user.username, user.otp_secret, req.body.code) ) {

        // THIS MAY BE COUNTER-INTUITIVE
        //
        // A successfully handled request, with the correct format,
        // but incorrect credentials when NOT using the HTTP
        // authentication framework provided by RFC 7235, SHOULD
        // return status 200.
        //
        // Source: I asked Julian Reschke in an email, and then he
        // contributed to this discussion:
        // https://stackoverflow.com/questions/32752578

        return res.status(200).send({
            proceed: false,
        });
    }

    return await complete_({ req, res, user });
});

router.post('/login/recovery-code', express.json(), body_parser_error_handler, async (req, res, next) => {
    // either api. subdomain or no subdomain
    if(require('../helpers').subdomain(req) !== 'api' && require('../helpers').subdomain(req) !== '')
        next();

    const svc_edgeRateLimit = req.services.get('edge-rate-limit');
    if ( ! svc_edgeRateLimit.check('login-recovery') ) {
        return res.status(429).send('Too many requests.');
    }

    if ( ! req.body.token ) {
        return res.status(400).send('token is required.');
    }

    if ( ! req.body.code ) {
        return res.status(400).send('code is required.');
    }

    const svc_token = req.services.get('token');
    let decoded; try {
        decoded = svc_token.verify('otp', req.body.token);
    } catch ( e ) {
        return res.status(400).send('Invalid token.');
    }

    if ( ! decoded.user_uid ) {
        return res.status(400).send('Invalid token.');
    }

    const user = await get_user({ uuid: decoded.user_uid, cached: false });
    if ( ! user ) {
        return res.status(400).send('User not found.');
    }

    const code = req.body.code;

    const crypto = require('crypto');

    const codes = user.otp_recovery_codes.split(',');
    const hashed_code = crypto
        .createHash('sha256')
        .update(code)
        .digest('base64')
        // We're truncating the hash for easier storage, so we have 128
        // bits of entropy instead of 256. This is plenty for recovery
        // codes, which have only 48 bits of entropy to begin with.
        .slice(0, 22);

    if ( ! codes.includes(hashed_code) ) {
        return res.status(200).send({
            proceed: false,
        });
    }

    // Remove the code from the list
    const index = codes.indexOf(hashed_code);
    codes.splice(index, 1);
    
    // update user
    const db = req.services.get('database').get(DB_WRITE, '2fa');
    await db.write(
        `UPDATE user SET otp_recovery_codes = ? WHERE uuid = ?`,
        [codes.join(','), user.uuid]
    );
    user.otp_recovery_codes = codes.join(',');

    return await complete_({ req, res, user });
});

module.exports = router;

import da from '../i18n/translations/da.js';
import UIWindow from './UIWindow.js';
import axios from 'axios';
import jwt from 'jsonwebtoken';

// Define Keycloak settings
const config = {
    clientId: 'Puter',
    clientSecret: 'RlPL4mR69umkOxqhudw1mdtS9vqq8TAf',
    realm: 'RealmOne',
    authServerUrl: 'http://localhost:8080',
    redirectUri: 'http://puter.localhost:4100/login' // Fixed the redirectUri
};

async function UIWindowLogin(options) {
    options = options ?? {};

    return new Promise(async (resolve) => {
        let h = ``;
        h += `<div style="max-width: 500px; min-width: 340px;">`;
        h += `<div style="padding: 20px; text-align: center;">`;
        h += `<h1 class="login-form-title">${i18n('log_in')}</h1>`;
        h += `<button class="login-btn button button-primary button-block button-normal">${i18n('log_in')}</button>`;
        h += `</div>`;
        h += `</div>`;

        const el_window = await UIWindow({
            title: null,
            app: 'login',
            single_instance: true,
            body_content: h,
            has_head: true,
            width: 350,
            dominant: true,
            on_close: () => resolve(false),
            window_class: 'window-login',
            window_css: {
                height: 'initial',
            },
            body_css: {
                padding: '0',
                'background-color': 'rgb(255 255 255)',
                'backdrop-filter': 'blur(3px)',
            }
        });

        $(el_window).find('.login-btn').on('click', async function(e) {
            try {
                // Check if the URL has an authorization code
                const urlParams = new URLSearchParams(window.location.search);
                const code = urlParams.get('code');

                if (!code) {
                    // Redirect to Keycloak login page if not authenticated
                    const authUrl = `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/auth` +
                        `?client_id=${config.clientId}` +
                        `&response_type=code` +
                        `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
                        `&scope=openid`;
                    window.location.href = authUrl;
                } else {
                    // Exchange the authorization code for tokens
                    const tokenResponse = await axios.post(
                        `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/token`,
                        new URLSearchParams({
                            grant_type: 'authorization_code',
                            client_id: config.clientId,
                            client_secret: config.clientSecret,
                            code: code,
                            redirect_uri: config.redirectUri
                        }),
                        {
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                        }
                    );

                    const tokens = tokenResponse.data;

                    // Decode the id_token to retrieve its payload
                    const idTokenPayload = jwt.decode(tokens.id_token);
                    const info = JSON.stringify(idTokenPayload, null, 2);
                    console.log('ID Token Payload:', info);

                    // Send a POST request with the token to /login
                    let headers = {};
                    if (window.custom_headers)
                        headers = window.custom_headers;

                    $.ajax({
                        url: window.gui_origin + '/login',
                        type: 'POST',
                        async: false,
                        headers: headers,
                        contentType: 'application/json',
                        data: JSON.stringify({ token: tokens.id_token }),
                        success: async function(data) {
                            window.update_auth_data(data.token, data.user);
                            if (options.reload_on_success) {
                                window.onbeforeunload = null;
                                window.location.replace('/');
                            } else
                                resolve(true);
                            $(el_window).close();
                        },
                        error: function(xhr, status, error) {
                            console.error('Error during login:', error);
                            resolve(false);
                        }
                    });
                }
            } catch (error) {
                console.error('Error checking authentication:', error);
                resolve(false);
            }
        });
    });
}

export default UIWindowLogin;
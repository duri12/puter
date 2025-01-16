import da from '../i18n/translations/da.js';
import UIWindow from './UIWindow.js';

// Define Keycloak settings
const keycloak = {
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
        h += `<button class="login-btn button button-primary button-block button-normal"><strong>${i18n('log_in')}</strong></button>`;
        h += `</div>`;
        
        // Check URL parameters and add them to the HTML content
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.toString()) {
            h += `<div style="padding: 20px; text-align: left; border: 1px solid #ccc; margin-top: 20px;">`;
            h += `<h2><strong>URL Parameters:</strong></h2>`;
            urlParams.forEach((value, key) => {
                h += `<p><strong>${key}:</strong> ${decodeURIComponent(value)}</p>`;
            });
            h += `</div>`;
        }
        h += `</div>`;
        
        const code = urlParams.get('code');
        if (code) {

            let headers = window.custom_headers || {};
            
            $.ajax({
                url: `${window.gui_origin}/login/keycloak`,
                type: 'POST',
                headers: headers,
                contentType: 'application/json',
                async: false,
                data: JSON.stringify({ code }),
                success: async function(data) {
                    
                    window.update_auth_data(data.token, data.user);
                    if (options.reload_on_success) {
                        window.onbeforeunload = null;
                        window.location.replace('/');
                    } else {
                        resolve(true);
                    }
                    
                },
                error: function(xhr, status, error) {
                    console.error('Error during login:', status, error);
                    resolve(false);
                }
            });
            
        }
        
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
            },
        });

        $(el_window).find('.login-btn').on('click', async function() {
            try {
                const authUrl = `${keycloak.authServerUrl}/realms/${keycloak.realm}/protocol/openid-connect/auth` +
                    `?client_id=${keycloak.clientId}` +
                    `&response_type=code` +
                    `&redirect_uri=${encodeURIComponent(keycloak.redirectUri)}` +
                    `&scope=openid`;

                window.location.href = authUrl;
            } catch (error) {
                console.error('Error redirecting to login:', error);
                resolve(false);
            }
        });
    });
}

export default UIWindowLogin;

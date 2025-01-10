import UIWindow from './UIWindow.js'

// Define Keycloak settings
const config = {
    clientId: 'Puter',
    clientSecret: 'RlPL4mR69umkOxqhudw1mdtS9vqq8TAf',
    realm: 'RealmOne',
    authServerUrl: 'http://localhost:8080',
    redirectUri: 'http://puter.localhost:4100/login' // Fixed the redirectUri
};

async function UIWindowLogin(options){
    options = options ?? {};
    
    return new Promise(async (resolve) => {
        let h = ``;
        h += `<div style="max-width: 500px; min-width: 340px;">`;
            h += `<div style="padding: 20px; text-align: center;">`;
                h += `<h1 class="login-form-title">${i18n('log_in')}</h1>`;
                h += `<button class="login-btn button button-primary button-block button-normal">${i18n('log_in')}</h1>`;
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
        })

        $(el_window).find('.login-btn').on('click', function(e){
            // Redirect to Keycloak login page
            const authUrl = `${config.authServerUrl}/realms/${config.realm}/protocol/openid-connect/auth` +
            `?client_id=${config.clientId}` +
            `&response_type=code` +
            `&redirect_uri=${encodeURIComponent(config.redirectUri)}` +
            `&scope=openid`;
            window.location.href = authUrl;
        })
    }) 
}

export default UIWindowLogin